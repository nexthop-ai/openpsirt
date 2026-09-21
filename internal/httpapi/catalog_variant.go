package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

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
				issued, err := vex.AnyIssuedForVariant(ctx, tx, variant.ID)
				if err != nil {
					return wentWrong(d.Logger, "that variant could not be renamed", err)
				}
				if issued {
					return huma.NewError(http.StatusConflict,
						"a document naming this variant has been published, so its name "+
							"is what readers already hold it by. Retire it and declare the "+
							"intended name instead.")
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

// reaches names the two states in the words the record is read in.
func reaches(customerFacing bool) string {
	if customerFacing {
		return "reaches customers"
	}
	return "internal only"
}
