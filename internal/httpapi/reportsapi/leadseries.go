// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// LeadSeriesBody is how many leads one analyzer series holds, by state.
type LeadSeriesBody struct {
	Series  string         `json:"series" doc:"The series' name, as its producer first sent it"`
	States  map[string]int `json:"states" doc:"The series' leads by where they stand, every state named. A lead on two builds in two states counts in both"`
	Waiting int            `json:"waiting" doc:"Open leads a claim waiting for a second person leaves out of the queue, counted among the open in states"`
	Ruled   int            `json:"ruled" doc:"Dismissed leads an approved standing rule covers, counted among the dismissed in states"`
}

func registerLeadSeries(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-lead-series", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-finding-series",
		Summary: "Count code findings by analyzer series",
		Description: "Returns one entry per analyzer series the product holds, ordered by name, " +
			"with how many of its code findings stand in each state across every build of the product. " +
			"A series with no code findings is listed with every count zero.\n\n" +
			"Each count is the total the code finding list answers for the same `series` and `state`.\n\n" +
			"Refused, with no count, to anybody who does not read internal material in the product.",
		Tags: []string{"Reports"},
	}, core.AnyPerson, "Requires internal-read on the product."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*struct {
		Body struct {
			Items []LeadSeriesBody `json:"items"`
		}
	}, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		scope, err := core.Scoped(ctx, in, subject, core.ScopeQuery{Product: input.Product})
		if err != nil {
			return nil, err
		}
		counted, err := analysis.CountsBySeries(ctx, in.DB.DB, subject, *scope.ProductID)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot count the leads")
		}
		out := &struct {
			Body struct {
				Items []LeadSeriesBody `json:"items"`
			}
		}{}
		out.Body.Items = make([]LeadSeriesBody, 0, len(counted))
		for _, each := range counted {
			states := make(map[string]int, len(each.ByState))
			for state, n := range each.ByState {
				states[string(state)] = n
			}
			out.Body.Items = append(out.Body.Items, LeadSeriesBody{
				Series: each.Series, States: states, Waiting: each.Waiting, Ruled: each.Ruled,
			})
		}
		return out, nil
	})
}
