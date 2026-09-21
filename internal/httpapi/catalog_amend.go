package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// registerVariantEdits registers the two writes that correct a variant and
// take one out of use.
//
// Both are administrator writes. A variant decides what a scan may name, what
// every picker offers and how a finding ranks, so neither is something a
// pipeline reaches: declaring is the act a build runs, and these are the acts
// somebody makes deliberately.
func registerVariantEdits(api huma.API, d Declaring) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "amend-variant", Method: http.MethodPatch,
		Path:    "/v1/products/{product}/variants/{variant}",
		Summary: "Amend a build variant",
		Description: "Corrects what a variant is called and whether it reaches customers. " +
			"Both are left alone where the request omits them.\n\n" +
			"A name is refused once an OpenVEX document has been published for any release " +
			"built as this variant. A document is identified by the build it describes, so a " +
			"reader who already holds one would read the next as a different document rather " +
			"than as a revision, and the record of what went out names no name to correct. " +
			"Retire the variant and declare the intended one instead.\n\n" +
			"Whether it reaches customers feeds how its findings rank, and may be corrected " +
			"at any time. A name another variant of this product holds is refused, including " +
			"one that is retired.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Variant string `path:"variant"`
		Body    struct {
			Name string `json:"name,omitempty" maxLength:"191" doc:"What to call it instead. Omitted leaves the name alone"`
			// A pointer for the reason declaring one uses a pointer: absent
			// and no are different requests, and this one changes ranking.
			CustomerFacing *bool `json:"customer_facing,omitempty" doc:"Whether it reaches customers. Omitted leaves it alone"`
		}
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		name := strings.TrimSpace(in.Body.Name)
		if name == "" && in.Body.CustomerFacing == nil {
			return nil, huma.Error400BadRequest(
				"say what to change: a name, whether it reaches customers, or both")
		}
		// Both writes and the record of them in one transaction, with every
		// name resolved inside it. Renaming and reclassifying apart leaves the
		// first standing when the second fails, and the answer would describe
		// a state the database does not hold.
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, err := store.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			variant, err := store.VariantByName(ctx, product.ID, in.Variant)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			about := product.Name + " " + variant.Name

			if name != "" && !strings.EqualFold(name, variant.Name) {
				issued, err := published(ctx, tx, "variant", variant.ID)
				if err != nil {
					return wentWrong(d.Logger, "that variant could not be renamed", err)
				}
				if issued {
					return heldByReaders("variant")
				}
				if err := store.RenameVariant(ctx, product.ID, variant.ID, name); err != nil {
					return declineDeclaration(err)
				}
				if err := noted(ctx, tx, trail.Catalog, about,
					trail.Said(variant.Name, true), trail.Said(name, true)); err != nil {
					return notRecorded(d.Logger, err)
				}
				about = product.Name + " " + name
			}

			if facing := in.Body.CustomerFacing; facing != nil && *facing != variant.CustomerFacing {
				if err := store.SetVariantCustomerFacing(ctx, variant.ID, *facing); err != nil {
					return wentWrong(d.Logger, "that variant could not be changed", err)
				}
				if err := noted(ctx, tx, trail.Catalog, about,
					trail.Said(reaches(variant.CustomerFacing), true),
					trail.Said(reaches(*facing), true)); err != nil {
					return notRecorded(d.Logger, err)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retire-variant", Method: http.MethodDelete,
		Path:    "/v1/products/{product}/variants/{variant}",
		Summary: "Retire a build variant",
		Description: "Takes a variant out of use. It is offered nowhere and no scan may be " +
			"filed against it, while everything already filed against it stays: its findings " +
			"are still open, its decisions still stand, and the documents published for it " +
			"still name it. The releases it was built as still list it.\n\n" +
			"The name stays spoken for. Declaring it again brings this variant back rather " +
			"than making a second one, so a build that declares what it needs keeps working " +
			"and nothing is stranded.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Variant string `path:"variant"`
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, err := store.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			variant, err := store.VariantByName(ctx, product.ID, in.Variant)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			if err := store.RetireVariant(ctx, variant.ID); err != nil {
				if errors.Is(err, catalog.ErrNotFound) {
					// Already retired: the write is conditional on it being in
					// use, so nothing matched. Refused rather than answered as
					// done, so that two administrators retiring it at once do
					// not both record having done so.
					return huma.NewError(http.StatusConflict,
						"that variant is already retired")
				}
				return wentWrong(d.Logger, "that variant could not be retired", err)
			}
			if err := noted(ctx, tx, trail.Catalog, product.Name+" "+variant.Name,
				trail.Said("in use", true), nil); err != nil {
				return notRecorded(d.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// registerCatalogAmends registers the writes that correct a product and a
// release and take one out of use.
//
// Beside the variant's, which are the same two acts a level down. Split by
// what they act on rather than by verb, so that a level's rules — a product's
// display name moves freely, a release carries a support date that this is not
// — sit together.
func registerCatalogAmends(api huma.API, d Declaring) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "amend-product", Method: http.MethodPatch, Path: "/v1/products/{product}",
		Summary: "Amend a product",
		Description: "Corrects what a product is called. Both names are left alone where the " +
			"request omits them.\n\n" +
			"The name is what scans, paths and published documents use. It is refused once a " +
			"VEX document has gone out for any build of this product, or an advisory covering " +
			"it has been published: a reader who holds one matches it by that name, and the " +
			"record of what went out names no name to correct. Retire the product and declare " +
			"the intended one instead.\n\n" +
			"The displayed name is what screens show and what a document names the product in " +
			"prose. Nothing is identified by it, so it may be corrected at any time.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Body    struct {
			Name        string `json:"name,omitempty" maxLength:"191" doc:"What scans and paths should call it instead. Omitted leaves it alone"`
			DisplayName string `json:"display_name,omitempty" maxLength:"191" doc:"What screens and documents should show instead. Omitted leaves it alone"`
		}
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		name, shown := strings.TrimSpace(in.Body.Name), strings.TrimSpace(in.Body.DisplayName)
		if name == "" && shown == "" {
			return nil, huma.Error400BadRequest(
				"say what to change: the name, the displayed name, or both")
		}
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, err := store.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			if name != "" && !strings.EqualFold(name, product.Name) {
				issued, err := published(ctx, tx, "product", product.ID)
				if err != nil {
					return wentWrong(d.Logger, "that product could not be renamed", err)
				}
				if issued {
					return heldByReaders("product")
				}
				if err := store.RenameProduct(ctx, product.ID, name); err != nil {
					return declineDeclaration(err)
				}
				if err := noted(ctx, tx, trail.Catalog, product.Name,
					trail.Said(product.Name, true), trail.Said(name, true)); err != nil {
					return notRecorded(d.Logger, err)
				}
			}
			if shown != "" && shown != product.DisplayName {
				if err := store.SetProductDisplayName(ctx, product.ID, shown); err != nil {
					return declineDeclaration(err)
				}
				if err := noted(ctx, tx, trail.Catalog, product.Name,
					trail.Said(product.DisplayName, true), trail.Said(shown, true)); err != nil {
					return notRecorded(d.Logger, err)
				}
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retire-product", Method: http.MethodDelete, Path: "/v1/products/{product}",
		Summary: "Retire a product",
		Description: "Takes a product out of use. It is offered nowhere and no scan may be " +
			"filed against it, while everything already filed against it stays: its findings " +
			"are still open, its decisions still stand, and the documents published for it " +
			"still name it.\n\n" +
			"Its releases and variants are left as they are and go out of every list with it, " +
			"because they are reached through the product. Declaring the product again brings " +
			"it back with them.\n\n" +
			"Not an end-of-support date, which is beside this and says something else: a date " +
			"records that support ended and hides nothing, because a release is asked about " +
			"long after it stops being supported.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, err := store.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			if err := store.RetireProduct(ctx, product.ID); err != nil {
				if errors.Is(err, catalog.ErrNotFound) {
					return huma.NewError(http.StatusConflict, "that product is already retired")
				}
				return wentWrong(d.Logger, "that product could not be retired", err)
			}
			if err := noted(ctx, tx, trail.Catalog, product.Name,
				trail.Said("in use", true), nil); err != nil {
				return notRecorded(d.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "amend-stream", Method: http.MethodPatch,
		Path:    "/v1/products/{product}/streams/{stream}",
		Summary: "Amend a branch or tag",
		Description: "Corrects what a release is called.\n\n" +
			"Refused once a VEX document has gone out for any build of this release, or a " +
			"published advisory named it: a reader who holds one matches it by that name. " +
			"A release cannot be retired and declared again as a way round that, because the " +
			"second one holds none of this one's history.\n\n" +
			"Whether it is a branch or a tag does not move here, and neither does the branch a " +
			"tag was cut from. Both say what a release is rather than what it is called.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Body    struct {
			Name string `json:"name" minLength:"1" maxLength:"191" doc:"What to call it instead"`
		}
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		name := strings.TrimSpace(in.Body.Name)
		if name == "" {
			return nil, huma.Error400BadRequest("say what to call it")
		}
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, err := store.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			stream, err := store.StreamByName(ctx, product.ID, in.Stream)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			if strings.EqualFold(name, stream.Name) && name == stream.DisplayName {
				return nil
			}
			if !strings.EqualFold(name, stream.Name) {
				issued, err := published(ctx, tx, "release", stream.ID)
				if err != nil {
					return wentWrong(d.Logger, "that release could not be renamed", err)
				}
				if issued {
					return heldByReaders("release")
				}
			}
			if err := store.RenameStream(ctx, product.ID, stream.ID, name); err != nil {
				return declineDeclaration(err)
			}
			return noteOrFail(ctx, tx, d, product.Name+" "+stream.Name, name)
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retire-stream", Method: http.MethodDelete,
		Path:    "/v1/products/{product}/streams/{stream}",
		Summary: "Retire a branch or tag",
		Description: "Takes a release out of use. It is offered nowhere and no scan may be " +
			"filed against it, while everything already filed against it stays. Declaring it " +
			"again brings it back.\n\n" +
			"Not an end-of-support date, which is beside this: a date records that support " +
			"ended and hides nothing, because a release is asked about long after it stops " +
			"being supported. This says the release is not tracked here.",
		Tags: []string{"Catalog"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, in *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
	}) (*struct{}, error) {
		if err := administrating(ctx); err != nil {
			return nil, err
		}
		if err := changing(ctx, d.DB, d.Logger, func(ctx context.Context, tx bun.Tx) error {
			store, err := storeFor(d, tx)
			if err != nil {
				return err
			}
			product, err := store.ProductByName(ctx, in.Product)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			stream, err := store.StreamByName(ctx, product.ID, in.Stream)
			if err != nil {
				return undeclared(d.Logger, err, "that product could not be looked up")
			}
			if err := store.RetireStream(ctx, stream.ID); err != nil {
				if errors.Is(err, catalog.ErrNotFound) {
					return huma.NewError(http.StatusConflict, "that release is already retired")
				}
				return wentWrong(d.Logger, "that release could not be retired", err)
			}
			if err := noted(ctx, tx, trail.Catalog, product.Name+" "+stream.Name,
				trail.Said("in use", true), nil); err != nil {
				return notRecorded(d.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// noteOrFail records a rename and turns a failure to record it into the answer
// for one.
func noteOrFail(ctx context.Context, tx bun.Tx, d Declaring, was, became string) error {
	if err := noted(ctx, tx, trail.Catalog, was,
		trail.Said(was, true), trail.Said(became, true)); err != nil {
		return notRecorded(d.Logger, err)
	}
	return nil
}

// published reports whether anything naming this part of the catalog has gone
// out to a reader outside this deployment.
//
// One answer for the three levels, because the rule is one rule: a name a
// customer already holds a document by is not this deployment's to correct.
// Asked of both kinds of document — a VEX document is issued per build and an
// advisory per issue across releases, and either one carries the build's
// identifier.
//
// Given the handle the rename will be written on, so both run inside its
// transaction. A document issued between asking and renaming would otherwise
// be published under a name this had already said nothing was published under.
func published(ctx context.Context, db bun.IDB, level string, id int64) (bool, error) {
	var asked []func(context.Context, bun.IDB, int64) (bool, error)
	switch level {
	case "product":
		asked = []func(context.Context, bun.IDB, int64) (bool, error){
			vex.AnyIssuedForProduct, advisory.AnyIssuedForProduct,
		}
	case "release":
		asked = []func(context.Context, bun.IDB, int64) (bool, error){
			vex.AnyIssuedForStream, advisory.AnyIssuedForStream,
		}
	default:
		asked = []func(context.Context, bun.IDB, int64) (bool, error){
			vex.AnyIssuedForVariant,
		}
	}
	for _, ask := range asked {
		gone, err := ask(ctx, db, id)
		if err != nil {
			return false, err
		}
		if gone {
			return true, nil
		}
	}
	return false, nil
}

// heldByReaders is the refusal a name that has been published answers with.
//
// It names what to do instead, which is the part a caller can act on.
func heldByReaders(level string) error {
	return huma.NewError(http.StatusConflict,
		"a document naming this "+level+" has been published, so its name is what "+
			"readers already hold it by. Retire it and declare the intended name instead.")
}

// reaches names the two states in the words the record is read in.
func reaches(customerFacing bool) string {
	if customerFacing {
		return "reaches customers"
	}
	return "internal only"
}
