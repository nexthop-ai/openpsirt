// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
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
	core.HolderBody
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
		Ended   int            `json:"past_end_of_life" doc:"Open leads left out of the queue because every release they are open in is past its end of life. Zero for a list by state"`
	}
}

// LeadsAsked is the narrowing the lead queue takes, for the screen and for
// its file. One struct, because a file taking fewer filters than its list
// answers a different question under the same name.
type LeadsAsked struct {
	Product string    `path:"product"`
	Stream  string    `query:"stream" doc:"Limit to one branch or tag. Left out, every one under the product"`
	Variant string    `query:"variant" doc:"Limit to one variant. Left out, every one under the product, and independent of the branch"`
	Series  string    `query:"series" maxLength:"200" doc:"Limit to one analyzer series, by name, without regard to capitals. A name the product holds no series under lists nothing"`
	State   LeadState `query:"state" doc:"List the leads in one state. Left out, the queue"`
}

// scoped resolves what is asked for against what the reader may see. A
// product the reader may not read is refused here, before anything is read.
func (a LeadsAsked) scoped(ctx context.Context, in core.Deps) (access.Subject, analysis.Scope, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return subject, analysis.Scope{}, err
	}
	scope, err := core.Scoped(ctx, in, subject, core.ScopeQuery{
		Product: a.Product, Stream: a.Stream, Variant: a.Variant,
	})
	if err != nil {
		return subject, analysis.Scope{}, err
	}
	if _, err := access.Readable(subject, *scope.ProductID); err != nil {
		return subject, analysis.Scope{}, core.Refused(in.Logger, err, "cannot read the leads")
	}
	return subject, analysis.Scope{
		ProductID: *scope.ProductID, StreamID: scope.StreamID, VariantID: scope.VariantID,
		Series: strings.TrimSpace(a.Series),
	}, nil
}

// leadRows is a page of leads as the list and its file both state them, with
// who holds each one named.
func leadRows(ctx context.Context, in core.Deps, rows []analysis.QueueRow) ([]LeadRowBody, error) {
	parties := make([]int64, 0, len(rows))
	for _, r := range rows {
		if r.Holder != nil {
			parties = append(parties, *r.Holder)
		}
	}
	who, err := access.NewStore(in.DB.DB).WhoHolds(ctx, parties)
	if err != nil {
		return nil, err
	}
	out := make([]LeadRowBody, 0, len(rows))
	for _, r := range rows {
		row := LeadRowBody{
			Place: r.Place, Rule: r.Rule, Path: r.Path, Function: r.Function, Message: r.Message, Withheld: r.Stub,
			Stream: r.Stream, Variant: r.Variant, State: LeadState(r.State), Builds: r.Builds,
			Opened: r.Opened.UTC().Format(time.DateOnly),
		}
		if r.Line != nil {
			row.Line = *r.Line
		}
		if r.Holder != nil {
			row.HolderBody = core.HolderOf(who[*r.Holder])
		}
		out = append(out, row)
	}
	return out, nil
}

// leadColumns names the columns of the lead queue's file, in the order
// leadCells fills them.
func leadColumns() []string {
	return []string{
		"rule", "path", "line", "function", "message", "withheld", "state", "stream", "variant",
		"builds", "opened", "assigned_to", "place",
	}
}

// leadCells is one row of the lead queue's file. A line the analyzer named
// none for is an empty cell, never a zero.
func leadCells(row LeadRowBody) []string {
	line := ""
	if row.Line > 0 {
		line = strconv.Itoa(row.Line)
	}
	return []string{
		row.Rule, row.Path, line, row.Function, row.Message, strconv.FormatBool(row.Withheld),
		string(row.State), row.Stream, row.Variant, strconv.Itoa(row.Builds), row.Opened,
		row.AssignedTo, row.Place,
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
			"so what the list leaves out is counted. The queue also leaves out a lead open only in " +
			"releases past their end of life, and `past_end_of_life` counts those. A lead seen only in " +
			"such releases is kept as it stands: a decision, a fixed closure, pulling it in and handing " +
			"it off are refused with 409. " +
			"`stream`, `variant` and `series` are optional and independent. Supports limit and offset.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		LeadsAsked
		core.Paging
	}) (*LeadsOutput, error) {
		subject, scope, err := input.scoped(ctx, in)
		if err != nil {
			return nil, err
		}
		queue, err := analysis.LeadsOf(ctx, in.DB.DB, subject, scope, analysis.State(input.State),
			input.Limit, input.Offset)
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
		if out.Body.Items, err = leadRows(ctx, in, queue.Rows); err != nil {
			return nil, core.WentWrong(in.Logger, "who holds the leads could not be read", err)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-leads", Method: http.MethodGet,
		Path:    "/v1/products/{product}/leads.{format}",
		Summary: "Export static analysis leads",
		Description: "The lead list as a file: every row the same filters would list, not one " +
			"page of them, in the same order.\n\n" +
			"Read with your own visibility, as it is written. A lead in a case you are not on is " +
			"a row with an empty message and `withheld` true. No row carries source text.\n\n" +
			"With no `state` it is the queue, and the file says so. Takes every filter the lead " +
			"list takes.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		LeadsAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		// Refused before the first byte, so a refusal is a status rather
		// than a line in a file that answered 200.
		subject, scope, err := input.scoped(ctx, in)
		if err != nil {
			return nil, err
		}
		listing := "the queue: open leads nothing waits on, the baseline and leads open only in releases past their end of life left out"
		if input.State != "" {
			listing = "the leads " + string(input.State)
		}
		out := core.Exporting{
			What:   "leads",
			About:  []core.Stated{{Label: "lists", Value: listing}},
			Header: leadColumns(),
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				queue, err := analysis.LeadsOf(ctx, in.DB.DB, subject, scope, analysis.State(input.State),
					limit, offset)
				if err != nil {
					return nil, err
				}
				listed, err := leadRows(ctx, in, queue.Rows)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(listed))
				for _, row := range listed {
					rows = append(rows, leadCells(row))
				}
				return rows, nil
			},
		}
		name := "leads-" + strings.ToLower(input.Product)
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, name, out)
		}}, nil
	})
}
