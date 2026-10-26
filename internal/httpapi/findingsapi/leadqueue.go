// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// LeadRowBody is one lead in a product's list of them.
type LeadRowBody struct {
	Place    string    `json:"place" doc:"The lead's place identity, which addresses it on every build it is on"`
	Rule     string    `json:"rule" doc:"The analyzer's rule, as <tool>/<rule>"`
	Path     string    `json:"path" doc:"The file, from the top of the checkout"`
	Line     int       `json:"line,omitempty" doc:"The line the result starts at"`
	Function string    `json:"function,omitempty" doc:"The function the result is in, where the analyzer names one"`
	Message  string    `json:"message" doc:"What the analyzer says. Empty where the lead is withheld"`
	Withheld bool      `json:"withheld,omitempty" doc:"Whether the lead is part of a case you are not on, so what the analyzer said is not answered"`
	Stream   string    `json:"stream" doc:"The branch or tag of the newest build the lead is listed on, to link to"`
	Variant  string    `json:"variant" doc:"The variant of that build"`
	State    LeadState `json:"state" doc:"Where the lead stands on that build"`
	Builds   int       `json:"builds" doc:"The number of builds in the list's scope the lead is listed on, in the state the list asks for"`
	Opened   string    `json:"opened" format:"date" doc:"When the lead was first opened on any of them"`
}

// LeadsOutput is a page of a product's leads.
type LeadsOutput struct {
	Body struct {
		Items []LeadRowBody `json:"items"`
		Total int           `json:"total" doc:"The leads the list holds"`
		// Counted rather than only listed, so that a list leaving the
		// baseline out says how much it left (REQ-30).
		States  map[string]int `json:"states" doc:"The leads in the scope by where they stand, the listed ones included. A lead on two builds in two states counts in both, and a fixed lead counts until it opens anew on its build"`
		Waiting int            `json:"waiting" doc:"Open leads left out of the queue because a claim about them waits for a second person"`
		Ruled   int            `json:"ruled" doc:"Dismissed leads an approved standing rule covers, counted among the dismissed in states"`
		Ended   int            `json:"past_end_of_life" doc:"Open leads left out of the queue because every release they were seen in is past its end of life. Zero for a list by state"`
	}
}

func registerLeadQueue(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-leads", Method: http.MethodGet,
		Path:    "/v1/products/{product}/leads",
		Summary: "List static analysis leads",
		Description: "Returns one row per lead the product holds, however many builds it is " +
			"on. Ordered by the tier of the weaknesses the rule names, then whether another analyzer " +
			"reports the same flaw on the build, then the tool's own security severity for the rule, " +
			"then its precision, then newest first.\n\n" +
			"With no `state` it is the queue: open leads with no claim waiting for a second " +
			"person. A lead in the baseline is left out until it is pulled in, its path is " +
			"marked important, or another analyzer reports the same flaw. `state` lists the leads " +
			"in one state instead, which is how the baseline is searched. `fixed` lists the leads " +
			"closed on a build and not opened anew there.\n\n" +
			"`states` counts every lead in the scope by state and `waiting` the open ones " +
			"left out for a waiting claim, and `ruled` the dismissed ones a standing rule covers, " +
			"so what the list leaves out is counted. The queue also leaves out a lead seen only in " +
			"releases past their end of life, and `past_end_of_life` counts those. Such a lead is kept as it " +
			"stands: a decision, a fixed closure, pulling it in and handing it off are refused with 409. " +
			"`stream` and `variant` are optional and independent. Supports limit and offset.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string    `path:"product"`
		Stream  string    `query:"stream" doc:"Limit to one branch or tag. Left out, every one under the product"`
		Variant string    `query:"variant" doc:"Limit to one variant. Left out, every one under the product, and independent of the branch"`
		State   LeadState `query:"state" doc:"List the leads in one state. Left out, the queue"`
		core.Paging
	}) (*LeadsOutput, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		scope, err := core.Scoped(ctx, in, subject, core.ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		})
		if err != nil {
			return nil, err
		}
		queue, err := analysis.LeadsOf(ctx, in.DB.DB, subject, analysis.Scope{
			ProductID: *scope.ProductID, StreamID: scope.StreamID, VariantID: scope.VariantID,
		}, analysis.State(input.State), input.Limit, input.Offset)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot read the leads")
		}
		out := &LeadsOutput{}
		out.Body.Total, out.Body.Waiting, out.Body.Ruled = queue.Total, queue.Waiting, queue.Ruled
		out.Body.Ended = queue.Ended
		out.Body.States = map[string]int{}
		for state, n := range queue.ByState {
			out.Body.States[string(state)] = n
		}
		out.Body.Items = make([]LeadRowBody, 0, len(queue.Rows))
		for _, r := range queue.Rows {
			row := LeadRowBody{
				Place: r.Place, Rule: r.Rule, Path: r.Path, Function: r.Function, Message: r.Message, Withheld: r.Stub,
				Stream: r.Stream, Variant: r.Variant, State: LeadState(r.State), Builds: r.Builds,
				Opened: r.Opened.UTC().Format(time.DateOnly),
			}
			if r.Line != nil {
				row.Line = *r.Line
			}
			out.Body.Items = append(out.Body.Items, row)
		}
		return out, nil
	})
}
