package httpapi

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// ScopeQuery is what the picker selected, as the screens that span products
// receive it.
//
// Every level is optional and empty means all of them, which is what an
// unselected level means. Embedded rather than repeated so the three screens
// that take it cannot drift into describing it differently.
type ScopeQuery struct {
	Product string `query:"product" doc:"Limit to one product, by name. Empty means every product you can see"`
	Stream  string `query:"stream" doc:"Limit to one branch or tag. Only meaningful with a product"`
	Variant string `query:"variant" doc:"Limit to one variant. Only meaningful with a product, and independent of the branch"`
}

// scoped resolves a selection into identifiers.
//
// Names are turned into identifiers through the catalog, which owns the rule
// for matching one — a second copy of that rule here is how two screens come
// to disagree about whether a name is the same name.
//
// A branch or variant without a product is refused rather than guessed at. It
// cannot be reached through the interface, which leaves those unselectable
// until a product is chosen, and guessing which product was meant is how a
// number quietly answers a different question from the one on screen.
func scoped(ctx context.Context, in Ingest, subject access.Subject, q ScopeQuery) (finding.Scope, error) {
	scope, sees, err := resolveScope(ctx, in, subject, q)
	if err != nil {
		return finding.Scope{}, err
	}
	if !sees {
		// The same answer either way. A product somebody may not see reads as
		// one that was never declared, so this cannot be used to find out
		// which products exist.
		return finding.Scope{}, noSuchProduct()
	}
	return scope, nil
}

// scopedByHolding is scoped for a read narrowed by what somebody holds rather
// than by what they may read.
//
// **A capability held without a read role reaches no product**, and what gives
// it content is what has been assigned to them. Refusing the scope
// because they cannot read the product refuses them their own work, which is
// the one thing they do have — so the check moves to the answer: it is the
// caller's job to turn an empty result for a product they cannot see back into
// "no such product", which keeps the property the ordinary check exists for.
//
// It reports whether they see the product, because that is what the caller
// needs in order to do it.
func scopedByHolding(ctx context.Context, in Ingest, subject access.Subject,
	q ScopeQuery) (finding.Scope, bool, error) {

	return resolveScope(ctx, in, subject, q)
}

// resolveScope turns names into identifiers and says whether the subject reads
// the product, without deciding what to do about it.
func resolveScope(ctx context.Context, in Ingest, subject access.Subject,
	q ScopeQuery) (finding.Scope, bool, error) {

	var scope finding.Scope
	if q.Product == "" {
		if q.Stream != "" || q.Variant != "" {
			return scope, false, huma.Error422UnprocessableEntity(
				"a branch or a variant needs a product to belong to — name one, or leave all three empty")
		}
		return scope, true, nil
	}

	names := catalog.NewStore(in.DB.DB)
	product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, q.Product)
	if err != nil {
		return finding.Scope{}, false, absent(in.Logger, err, "that product could not be looked up", noSuchProduct)
	}
	sees := subject.Sees(product.ID)
	scope.ProductID = &product.ID

	if q.Stream != "" {
		stream, err := names.StreamByName(ctx, product.ID, q.Stream)
		if err != nil {
			// A product they cannot see answers about its branches the way it
			// answers about itself, so a refusal here says nothing a refusal
			// on the product did not.
			if !sees {
				return finding.Scope{}, false, noSuchProduct()
			}
			return finding.Scope{}, false, huma.Error404NotFound(
				"that product has no branch or tag by that name")
		}
		scope.StreamID = &stream.ID
	}
	if q.Variant != "" {
		variant, err := names.VariantByName(ctx, product.ID, q.Variant)
		if err != nil {
			if !sees {
				return finding.Scope{}, false, noSuchProduct()
			}
			return finding.Scope{}, false, huma.Error404NotFound(
				"that product has no variant by that name")
		}
		scope.VariantID = &variant.ID
	}
	return scope, sees, nil
}
