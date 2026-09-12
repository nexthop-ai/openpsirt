package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/saved"
)

// SavedBody is a narrowing somebody kept.
type SavedBody struct {
	Name string `json:"name" minLength:"1" maxLength:"120" doc:"What to call it. Matched without regard to capitals, and one of a name replaces the one before"`
	// Query is the list's own query string, without a leading "?". Kept as
	// text because the filters belong to the list: a saved filter is a way
	// back to one, and the list is what knows how to read it.
	Query string `json:"query" maxLength:"2000" doc:"The findings list's query string, without a leading ?"`
	// Prepares is the claim this filter offers, where it offers one.
	Prepares *PreparedBody `json:"prepares,omitempty" doc:"What this filter offers to claim about what it catches. Absent on an ordinary saved filter, which is most of them"`
}

// PreparedBody is the claim a saved filter prepares.
//
// **A rule prepares a claim; a person proposes it.** These are offered
// prefilled and a named person submits the claim as their own, for a second
// person to approve. The wider form — a rule proposing its own pending claim,
// marked as proposed by the rule — was argued for and refused: it leaves the
// approver as the only human judgment on the claim, which is what making the
// claim the approver's unit was meant to prevent, and it puts a configuration file where a name belongs in
// the record. The difference shows up on the day a dismissal turns out to have
// been wrong and somebody asks who made it.
type PreparedBody struct {
	Outcome       string `json:"outcome" enum:"affected,not-applicable,deferred,wont-fix,already-fixed" doc:"What it offers to say"`
	Justification string `json:"justification,omitempty" doc:"The recognized reason it does not apply, where the outcome takes one"`
	// Reasoning is required, because it is what somebody will be putting
	// their name to: a prefill with an empty argument is a button that
	// proposes a dismissal saying nothing.
	Reasoning string `json:"reasoning" minLength:"1" maxLength:"10000" doc:"The words it offers. Required: this is what whoever submits it is putting their name to"`
	DeferDays int    `json:"defer_days,omitempty" minimum:"1" maximum:"3650" doc:"How long a deferral it prepares, in days from whenever somebody submits it. A date would be wrong the week after it was saved. Required where the outcome is a deferral, because the form works the date out from it; dropped where the outcome is anything else"`
}

func registerSaved(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-saved-filters", Method: http.MethodGet,
		Path:    "/v1/products/{product}/saved-filters",
		Summary: "List your saved filters",
		Description: "The narrowings you have kept, by name.\n\n" +
			"**Personal, and nothing is shared.** No ownership, no permissions and no arguing " +
			"about whose filter is authoritative — which is also what lets somebody keep one " +
			"that is half-formed. Yours are the only ones this answers with, whoever asks.\n\n" +
			"A saved filter naming something the list no longer offers simply stops narrowing " +
			"by it, which is a way back to a slightly wider list rather than a refusal to open " +
			"one.\n\n" +
			"**Kept per product.** A filter narrows one product's findings list and its query " +
			"names branches and variants that usually exist in no other, so one offered " +
			"everywhere would be offered where it matches nothing.",
		Tags: []string{"Findings"},
	}, anySubject, "Answers your own and nobody else's."),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
		}) (*listOutput[SavedBody], error) {
			who, store, err := keeping(ctx, in)
			if err != nil {
				return nil, err
			}
			product, err := filtersFor(ctx, in, input.Product)
			if err != nil {
				return nil, err
			}
			kept, err := store.SavedFilters(ctx, who.ID, product)
			if err != nil {
				return nil, wentWrong(in.Logger, "what you have kept could not be read", err)
			}
			out := &listOutput[SavedBody]{}
			out.Body.Items = make([]SavedBody, 0, len(kept))
			for _, one := range kept {
				body := SavedBody{Name: one.Called(), Query: one.Query}
				if one.Prepares() {
					body.Prepares = &PreparedBody{
						Outcome: one.Outcome, Justification: one.Justification,
						Reasoning: one.Reasoning, DeferDays: one.DeferDays,
					}
				}
				out.Body.Items = append(out.Body.Items, body)
			}
			return out, nil
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "save-filter", Method: http.MethodPut,
		Path:    "/v1/products/{product}/saved-filters/{name}",
		Summary: "Keep a filter under a name",
		Description: "Keeps the findings list's current narrowing so it can be opened again. " +
			"Saving under a name you already use replaces it: the act is deciding what that " +
			"name means, and refusing would make somebody delete before they could correct.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, anySubject, "Yours alone."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Name    string `path:"name" maxLength:"120"`
		Body    struct {
			Query string `json:"query" maxLength:"2000" doc:"The list's query string, without a leading ?"`
			// Prepares is what the filter should offer to claim
			// about what it catches. Left out, it prepares nothing
			// — and left out on a filter that used to prepare
			// something takes that off, because saving over a name
			// is deciding what the name means now.
			Prepares *PreparedBody `json:"prepares,omitempty" doc:"What this filter should offer to claim about what it catches. Left out, it prepares nothing — including on a name that used to"`
		}
	}) (*struct{}, error) {
		who, store, err := keeping(ctx, in)
		if err != nil {
			return nil, err
		}
		var prepares saved.Filter
		if input.Body.Prepares != nil {
			prepares = saved.Filter{
				Outcome:       input.Body.Prepares.Outcome,
				Justification: input.Body.Prepares.Justification,
				Reasoning:     input.Body.Prepares.Reasoning,
				DeferDays:     input.Body.Prepares.DeferDays,
			}
		}
		product, err := filtersFor(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		if _, err := store.SaveFilterPreparing(ctx, who.ID, product, input.Name,
			input.Body.Query, prepares); err != nil {
			return nil, asked(in.Logger, err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "forget-filter", Method: http.MethodDelete,
		Path:    "/v1/products/{product}/saved-filters/{name}",
		Summary: "Forget a saved filter",
		Description: "Drops one of your own. A name you have not kept is not there, which is " +
			"the same answer as somebody else's — the filters are personal, and the query " +
			"says so rather than only the screen.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, anySubject, "Yours alone."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Name    string `path:"name" maxLength:"120"`
	}) (*struct{}, error) {
		who, store, err := keeping(ctx, in)
		if err != nil {
			return nil, err
		}
		product, err := filtersFor(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		if err := store.ForgetFilter(ctx, who.ID, product, input.Name); err != nil {
			if errors.Is(err, saved.ErrNoSuchFilter) {
				return nil, huma.Error404NotFound(err.Error())
			}
			return nil, wentWrong(in.Logger, "that filter could not be forgotten", err)
		}
		return &struct{}{}, nil
	})
}

// keeping resolves whose filters these are, and the store they are kept in.
//
// A person rather than a subject: a saved filter belongs to somebody, and a
// pipeline's key is not somebody. A credential minted by a person keeps its
// owner's, which is what "personal" means when the person has two ways in.
func keeping(ctx context.Context, in Ingest) (access.Subject, *saved.Store, error) {
	who, err := reading(ctx)
	if err != nil {
		return access.Subject{}, nil, err
	}
	if who.Kind != access.Person {
		return access.Subject{}, nil, huma.Error403Forbidden(
			"a saved filter belongs to somebody, and this credential is not somebody")
	}
	if in.DB == nil {
		return access.Subject{}, nil, noDatabase(in.Logger)
	}
	return who, saved.NewStore(in.DB.DB), nil
}

// filtersFor resolves which product's filters these are.
//
// Visible rather than merely declared, like every other product a name in a
// path resolves to: a product somebody holds nothing on is one that was never
// declared as far as they are concerned. Nothing here is about what the
// product holds — the filters are personal — but the address still names one,
// and an address that answers differently for a name somebody holds nothing on
// is a way to read the product list.
func filtersFor(ctx context.Context, in Ingest, name string) (int64, error) {
	subject, err := reading(ctx)
	if err != nil {
		return 0, err
	}
	product, err := catalog.NewStore(in.DB.DB).VisibleProduct(ctx, subject, name)
	if err != nil {
		return 0, noSuchProduct()
	}
	return product.ID, nil
}
