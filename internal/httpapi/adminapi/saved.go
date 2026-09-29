// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/saved"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// SavedBody is a narrowing somebody kept.
type SavedBody struct {
	Name string `json:"name" minLength:"1" maxLength:"120" doc:"The name. Matched without regard to capitals, and one of a name replaces the one before"`
	// Query is the list's own query string, without a leading "?". Kept as
	// text because the filters belong to the list: a saved filter is a way
	// back to one, and the list is what knows how to read it.
	Query string `json:"query" maxLength:"2000" doc:"The findings list's query string, without a leading ?, and without the branch, the variant or anything naming one build or one run"`
	// Prepares is the claim this filter offers, where it offers one.
	Prepares *PreparedBody `json:"prepares,omitempty" doc:"The claim this filter offers about what it catches. Absent on an ordinary saved filter, which is most of them"`
}

// PreparedBody is the claim a saved filter prepares.
//
// A rule prepares a claim; a person proposes it. These are offered prefilled
// and a named person submits the claim as their own, for a second person to
// approve. The wider form — a rule proposing its own pending claim, marked as
// proposed by the rule — is refused: it leaves the approver as the only human
// judgment on the claim, which is what making the claim the approver's unit
// exists to prevent, and it puts a configuration file where a name belongs in
// the record. The difference shows up on the day a dismissal turns out to have
// been wrong and somebody asks who made it.
type PreparedBody struct {
	Outcome       core.OutcomeInBulk `json:"outcome" doc:"The outcome it offers"`
	Justification core.Justification `json:"justification,omitempty" doc:"The recognized reason it does not apply, where the outcome takes one"`
	// Reasoning is required, because it is what somebody will be putting
	// their name to: a prefill with an empty argument is a button that
	// proposes a dismissal saying nothing.
	Reasoning string `json:"reasoning" minLength:"1" maxLength:"10000" doc:"The words it offers. Required: this is what whoever submits it is putting their name to"`
	DeferDays int    `json:"defer_days,omitempty" minimum:"1" maximum:"3650" doc:"The deferral it prepares, in days from whenever somebody submits it. A date would be wrong the week after it was saved. Required where the outcome is a deferral, and refused where it is anything else"`
}

func registerSaved(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-saved-filters", Method: http.MethodGet,
		Path:    "/v1/session/me/saved-filters",
		Summary: "List your saved filters",
		Description: "The narrowings you have kept, by name.\n\n" +
			"Personal, and nothing is shared. No ownership, no permissions and no arguing " +
			"about whose filter is authoritative — which is also what lets somebody keep one " +
			"that is half-formed. Yours are the only ones this answers with, whoever asks.\n\n" +
			"A saved filter naming something the list no longer offers simply stops narrowing " +
			"by it, which is a way back to a slightly wider list rather than a refusal to open " +
			"one.\n\n" +
			"At most as many as the per-person limit, in name order. `total` is how many you " +
			"keep, which is more than the list holds where the limit was lowered after they " +
			"were saved.\n\n" +
			"One list per person, for every findings list. A filter applies within whichever " +
			"product, branch and variant the list is scoped to.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers your own and nobody else's."),
		func(ctx context.Context, _ *struct{}) (*core.ListOutput[SavedBody], error) {
			who, store, err := keeping(ctx, in)
			if err != nil {
				return nil, err
			}
			cap, err := setting.NewStore(in.DB.DB).Count(ctx, setting.SavedPerPerson,
				setting.DefaultSavedPerPerson)
			if err != nil {
				return nil, core.WentWrong(in.Logger, "what you have kept could not be read", err)
			}
			kept, total, err := store.SavedFilters(ctx, who.ID, cap)
			if err != nil {
				return nil, core.WentWrong(in.Logger, "what you have kept could not be read", err)
			}
			out := &core.ListOutput[SavedBody]{}
			out.Body.Total = total
			out.Body.Items = make([]SavedBody, 0, len(kept))
			for _, one := range kept {
				body := SavedBody{Name: one.Called(), Query: one.Query}
				if one.Prepares() {
					body.Prepares = &PreparedBody{
						Outcome: core.OutcomeInBulk(one.Outcome), Justification: core.Justification(one.Justification),
						Reasoning: one.Reasoning, DeferDays: one.DeferDays,
					}
				}
				out.Body.Items = append(out.Body.Items, body)
			}
			return out, nil
		})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "save-filter", Method: http.MethodPut,
		Path:    "/v1/session/me/saved-filters/{name}",
		Summary: "Keep a filter under a name",
		Description: "Keeps the findings list's current narrowing so it can be opened again. " +
			"Saving under a name you already use replaces it: the act is deciding what that " +
			"name means, and refusing would make somebody delete before they could correct.\n\n" +
			"The branch, the variant, anything naming one build or one run, and the grouping are " +
			"left out of what is kept: `stream`, `variant`, `beneath` and its three qualifiers, " +
			"`differs`, `variants`, `opened_by_run` and `view`. Every other parameter is kept " +
			"as sent.\n\n" +
			"Refused with 422 where adding the name would take you past the per-person limit.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.AnyPerson, "Yours alone."), func(ctx context.Context, input *struct {
		Name string `path:"name" maxLength:"120"`
		Body struct {
			Query string `json:"query" maxLength:"2000" doc:"The list's query string, without a leading ?. Its scope is left out of what is kept"`
			// Prepares is what the filter should offer to claim
			// about what it catches. Left out, it prepares nothing
			// — and left out on a filter that prepares something
			// takes that off, because saving over a name is
			// deciding what the name means now.
			Prepares *PreparedBody `json:"prepares,omitempty" doc:"The claim this filter should offer about what it catches. Left out, it prepares nothing — including on a name that used to"`
		}
	}) (*struct{}, error) {
		who, store, err := keeping(ctx, in)
		if err != nil {
			return nil, err
		}
		var prepares saved.Filter
		if input.Body.Prepares != nil {
			prepares = saved.Filter{
				Outcome:       string(input.Body.Prepares.Outcome),
				Justification: string(input.Body.Prepares.Justification),
				Reasoning:     input.Body.Prepares.Reasoning,
				DeferDays:     input.Body.Prepares.DeferDays,
			}
		}
		cap, err := setting.NewStore(in.DB.DB).Count(ctx, setting.SavedPerPerson,
			setting.DefaultSavedPerPerson)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "that filter could not be kept", err)
		}
		if _, err := store.SaveFilterPreparing(ctx, who.ID, input.Name,
			input.Body.Query, prepares, cap); err != nil {
			return nil, core.Asked(in.Logger, err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "forget-filter", Method: http.MethodDelete,
		Path:    "/v1/session/me/saved-filters/{name}",
		Summary: "Forget a saved filter",
		Description: "Drops one of your own. A name you have not kept is not there, which is " +
			"the same answer as somebody else's — the filters are personal, and the query " +
			"says so rather than only the screen.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.AnyPerson, "Yours alone."), func(ctx context.Context, input *struct {
		Name string `path:"name" maxLength:"120"`
	}) (*struct{}, error) {
		who, store, err := keeping(ctx, in)
		if err != nil {
			return nil, err
		}
		if err := store.ForgetFilter(ctx, who.ID, input.Name); err != nil {
			if errors.Is(err, saved.ErrNoSuchFilter) {
				return nil, huma.Error404NotFound(saved.ErrNoSuchFilter.Error())
			}
			return nil, core.WentWrong(in.Logger, "that filter could not be forgotten", err)
		}
		return &struct{}{}, nil
	})
}

// keeping resolves whose filters these are, and the store they are kept in.
//
// A person rather than a subject: a saved filter belongs to somebody, and a
// pipeline's key is not somebody. A credential minted by a person keeps its
// owner's, which is what "personal" means when the person has two ways in.
func keeping(ctx context.Context, in core.Deps) (access.Subject, *saved.Store, error) {
	who, err := core.Reading(ctx)
	if err != nil {
		return access.Subject{}, nil, err
	}
	if who.Kind != access.Person {
		return access.Subject{}, nil, huma.Error403Forbidden(
			"a saved filter belongs to somebody, and this credential is not somebody")
	}
	if in.DB == nil {
		return access.Subject{}, nil, core.NoDatabase(in.Logger)
	}
	return who, saved.NewStore(in.DB.DB), nil
}
