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
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// CodeFindingRowBody is one code finding in a product's list of them.
type CodeFindingRowBody struct {
	Occurrence  string           `json:"occurrence" doc:"The code finding's occurrence identity, which addresses it on every build it is on"`
	Rule        string           `json:"rule" doc:"The analyzer's rule, as <tool>/<rule>"`
	Path        string           `json:"path" doc:"The file, from the top of the checkout"`
	Line        int              `json:"line,omitempty" doc:"The line the result starts at"`
	Function    string           `json:"function,omitempty" doc:"The function the result is in, where the analyzer names one"`
	Message     string           `json:"message" doc:"What the analyzer says"`
	ThirdParty  bool             `json:"third_party,omitempty" doc:"Whether the code finding is in code the newest run that saw it declared third-party"`
	BranchOrTag string           `json:"branch_or_tag" doc:"The branch or tag of the newest build the code finding is listed on, to link to"`
	Variant     string           `json:"variant" doc:"The variant of that build"`
	Component   string           `json:"component" doc:"The component the code finding is placed on in that build: the one built from the repository its path is in, or the build itself"`
	Version     string           `json:"version,omitempty" doc:"That component's version, where it states one and the build still ships it at that version"`
	OnBuild     bool             `json:"on_build,omitempty" doc:"Whether the code finding is placed on the build itself, because its path is in no repository a component of the build was built from"`
	State       CodeFindingState `json:"state" doc:"Where the code finding stands on that build"`
	Builds      int              `json:"builds" doc:"The number of builds in the list's scope the code finding is listed on, in the state the list asks for"`
	Opened      string           `json:"opened" format:"date" doc:"When the code finding was first opened on any of them"`
	core.HolderBody
}

// CodeFindingsOutput is a page of a product's code findings.
type CodeFindingsOutput struct {
	Body struct {
		Items []CodeFindingRowBody `json:"items"`
		Total int                  `json:"total" doc:"The code findings the list holds"`
		// Counted rather than only listed, so that a list leaving code findings
		// out says how much it left (REQ-30).
		States  map[string]int `json:"states" doc:"The code findings in the scope by where they stand, the listed ones included. A code finding on two builds in two states counts in both, and a fixed code finding counts until it opens anew on its build"`
		Waiting int            `json:"waiting" doc:"Open code findings left out of the queue because a decision about them waits for a second person"`
		Ruled   int            `json:"ruled" doc:"Dismissed code findings an approved suppression rule covers, counted among the dismissed in states"`
		Ended   int            `json:"past_end_of_life" doc:"Open code findings left out of the queue because every release they are open in is past its end of life. Zero for a list by state"`
	}
}

// CodeFindingsAsked is the narrowing the code finding queue takes, for the screen and for
// its file. One struct, because a file taking fewer filters than its list
// answers a different question under the same name.
type CodeFindingsAsked struct {
	Product     string            `path:"product"`
	BranchOrTag string            `query:"branch_or_tag" doc:"Limit to one branch or tag. Left out, every one under the product"`
	Variant     string            `query:"variant" doc:"Limit to one variant. Left out, every one under the product, and independent of the branch"`
	Series      string            `query:"series" maxLength:"200" doc:"Limit to one analyzer series, by name, without regard to capitals. A name the product holds no series under lists nothing"`
	State       CodeFindingState  `query:"state" doc:"List the code findings in one state. Left out, the queue"`
	Method      CodeFindingMethod `query:"method" doc:"Limit to the code findings one testing method reported. Left out, every method. sast is static analysis"`
	// Assigned is the findings list's parameter and value for work nobody
	// holds, so the two read alike.
	Assigned         CodeFindingAssignee `query:"assigned" doc:"Limit to the code findings with no holder on the build each row names. Every count is then of those code findings"`
	Component        string              `query:"component" maxLength:"200" doc:"Limit to the code findings placed on one source package: a source of this name, or the source a binary of this name was built from, without regard to capitals, as the component page reads a name"`
	ComponentVersion string              `query:"component_version" maxLength:"200" doc:"Limit component to the source package at this version. Ignored without component"`
	Beneath          string              `query:"beneath" maxLength:"200" doc:"Limit to the code findings placed at this component or anywhere under it, by the walk the dependency tree counts with. A subtree is a walk over one build's edges, so this needs a branch or tag and a variant naming exactly one build. A name the build does not hold answers 404, and one it holds as more than one component answers 409 naming the choices"`
	BeneathVersion   string              `query:"beneath_version" maxLength:"200" doc:"The version, where the build holds that name at several"`
	BeneathEcosystem string              `query:"beneath_ecosystem" maxLength:"200" doc:"The ecosystem, for the few names a build holds at one version as two components"`
	BeneathNamespace string              `query:"beneath_namespace" maxLength:"200" doc:"The namespace, for the few names a build holds at one version in one ecosystem as two components"`
}

// scoped resolves what is asked for against what the reader may see. A
// product the reader may not read is refused here, before anything is read.
func (a CodeFindingsAsked) scoped(ctx context.Context, in core.Deps) (access.Subject, analysis.Scope, error) {
	subject, err := core.Reading(ctx)
	if err != nil {
		return subject, analysis.Scope{}, err
	}
	scope, err := core.Scoped(ctx, in, subject, core.ScopeQuery{
		Product: a.Product, BranchOrTag: a.BranchOrTag, Variant: a.Variant,
	})
	if err != nil {
		return subject, analysis.Scope{}, err
	}
	if _, err := access.Readable(subject, *scope.ProductID); err != nil {
		return subject, analysis.Scope{}, core.Refused(in.Logger, err, "cannot read the code findings")
	}
	out := analysis.Scope{
		ProductID: *scope.ProductID, BranchOrTagID: scope.BranchOrTagID, VariantID: scope.VariantID,
		Series: strings.TrimSpace(a.Series), Unassigned: a.Assigned == finding.HeldByNobody,
		Method: analysis.Method(a.Method),
	}
	if out.Component = strings.TrimSpace(a.Component); out.Component != "" {
		out.ComponentVersion = strings.TrimSpace(a.ComponentVersion)
	}
	// Resolved after the product is authorized: a name is looked up only in
	// a build the reader may read.
	build, beneath, err := core.BeneathAt(ctx, in, scope, strings.TrimSpace(a.Beneath), graph.Choice{
		Version: a.BeneathVersion, Ecosystem: a.BeneathEcosystem, Namespace: a.BeneathNamespace,
	})
	if err != nil {
		return subject, analysis.Scope{}, err
	}
	out.BuildID, out.Beneath = build, beneath
	return subject, out, nil
}

// codeFindingRows is a page of code findings as the list and its file both state them, with
// who holds each one named.
func codeFindingRows(ctx context.Context, in core.Deps, rows []analysis.QueueRow) ([]CodeFindingRowBody, error) {
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
	out := make([]CodeFindingRowBody, 0, len(rows))
	for _, r := range rows {
		row := CodeFindingRowBody{
			Occurrence: r.Occurrence, Rule: r.Rule, Path: r.Path, Function: r.Function, Message: r.Message,
			ThirdParty:  r.ThirdParty,
			BranchOrTag: r.BranchOrTag, Variant: r.Variant, State: CodeFindingState(r.State), Builds: r.Builds,
			Component: r.Component, Version: r.Version, OnBuild: r.OnBuild,
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

// codeFindingColumns names the columns of the code finding queue's file, in the order
// codeFindingCells fills them.
func codeFindingColumns() []string {
	return []string{
		"rule", "path", "line", "function", "message", "state", "branch_or_tag", "variant",
		"builds", "opened", "assigned_to", "assigned_to_name", "assigned_team", "occurrence", "third_party",
		"component", "version", "on_build",
	}
}

// codeFindingCells is one row of the code finding queue's file. A line the analyzer named
// none for is an empty cell, never a zero.
func codeFindingCells(row CodeFindingRowBody) []string {
	line := ""
	if row.Line > 0 {
		line = strconv.Itoa(row.Line)
	}
	return []string{
		row.Rule, row.Path, line, row.Function, row.Message,
		string(row.State), row.BranchOrTag, row.Variant, strconv.Itoa(row.Builds), row.Opened,
		row.AssignedTo, row.AssignedName, strconv.FormatBool(row.AssignedTeam), row.Occurrence,
		strconv.FormatBool(row.ThirdParty), row.Component, row.Version, strconv.FormatBool(row.OnBuild),
	}
}

func registerCodeFindingQueue(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-code-findings", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-findings",
		Summary: "List code findings",
		Description: "Returns one row per code finding the product holds, however many builds it is " +
			"on. Ordered by the tier of the weaknesses the rule names, then whether another analyzer " +
			"reports the same flaw on the build, then the tool's own security severity for the rule, " +
			"then its precision, then newest first.\n\n" +
			"With no `state` it is the queue: open code findings with no decision waiting for a second " +
			"person. `state` lists the code findings in one state instead. `fixed` lists the code findings " +
			"closed on a build and not opened anew there.\n\n" +
			"`states` counts every code finding in the scope by state and `waiting` the open ones " +
			"left out for a waiting decision, and `ruled` the dismissed ones a suppression rule covers, " +
			"so what the list leaves out is counted. The queue also leaves out a code finding open only in " +
			"releases past their end of life, and `past_end_of_life` counts those. A code finding seen only in " +
			"such releases is kept as it stands: a decision, a fixed closure, an assignment and recording " +
			"it as a flaw are refused with 409. " +
			"`branch_or_tag`, `variant`, `series` and `method` are optional and independent. `component` keeps " +
			"the code findings placed on one source package, by its name or a binary's. `beneath` keeps those " +
			"placed at a component or under it on one build, which needs a branch or tag and a variant. " +
			"`assigned=nobody` keeps " +
			"the code findings nobody holds on the build each row names, and combines with every other filter. " +
			"Supports limit and offset.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		CodeFindingsAsked
		core.Paging
	}) (*CodeFindingsOutput, error) {
		subject, scope, err := input.scoped(ctx, in)
		if err != nil {
			return nil, err
		}
		queue, err := analysis.CodeFindingsOf(ctx, in.DB.DB, subject, scope, analysis.State(input.State),
			input.Limit, input.Offset)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot read the code findings")
		}
		out := &CodeFindingsOutput{}
		out.Body.Total, out.Body.Waiting, out.Body.Ruled = queue.Total, queue.Waiting, queue.Ruled
		out.Body.Ended = queue.Ended
		out.Body.States = map[string]int{}
		for state, n := range queue.ByState {
			out.Body.States[string(state)] = n
		}
		if out.Body.Items, err = codeFindingRows(ctx, in, queue.Rows); err != nil {
			return nil, core.WentWrong(in.Logger, "who holds the code findings could not be read", err)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-code-findings", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-findings.{format}",
		Summary: "Export code findings",
		Description: "The code finding list as a file: every row the same filters would list, not one " +
			"page of them, in the same order.\n\n" +
			"Read with your own visibility, as it is written. No row carries source text.\n\n" +
			"With no `state` it is the queue, and the file says so. Takes every filter the code finding " +
			"list takes.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		CodeFindingsAsked
		Format string `path:"format" enum:"csv,json"`
	}) (*huma.StreamResponse, error) {
		// Refused before the first byte, so a refusal is a status rather
		// than a line in a file that answered 200.
		subject, scope, err := input.scoped(ctx, in)
		if err != nil {
			return nil, err
		}
		listing := "the queue: open code findings nothing waits on, code findings open only in releases past their end of life left out"
		if input.State != "" {
			listing = "the code findings " + string(input.State)
		}
		if input.Assigned == finding.HeldByNobody {
			listing += ", nobody holding them"
		}
		if scope.Component != "" {
			listing += ", placed on " + scope.Component
			if scope.ComponentVersion != "" {
				listing += " " + scope.ComponentVersion
			}
		}
		if scope.Beneath != nil {
			listing += ", at or beneath " + strings.TrimSpace(input.Beneath)
		}
		out := core.Exporting{
			What:   "code findings",
			About:  []core.Stated{{Label: "lists", Value: listing}},
			Header: codeFindingColumns(),
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				queue, err := analysis.CodeFindingsOf(ctx, in.DB.DB, subject, scope, analysis.State(input.State),
					limit, offset)
				if err != nil {
					return nil, err
				}
				listed, err := codeFindingRows(ctx, in, queue.Rows)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(listed))
				for _, row := range listed {
					rows = append(rows, codeFindingCells(row))
				}
				return rows, nil
			},
		}
		name := "code findings-" + strings.ToLower(input.Product)
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, name, out)
		}}, nil
	})
}
