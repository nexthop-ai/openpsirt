// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// ComponentMatchBody is one source package a search names in one product.
type ComponentMatchBody struct {
	Product      string `json:"product"`
	Component    string `json:"component" doc:"The source package, as a producer spelled it. The component page answers for it by this name"`
	Issues       *int   `json:"issues,omitempty" doc:"Distinct vulnerabilities open on it in the builds searched, of what you read. Absent where you read no dependency finding in the product"`
	CodeFindings *int   `json:"code_findings,omitempty" doc:"Open code findings placed on it in the builds searched, the ones a decision waits on included. Absent where you do not read security testing material in the product"`
}

func registerComponentChooser(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "find-components", Method: http.MethodGet,
		Path:    "/v1/components",
		Summary: "Find components by name",
		Description: "Returns the source packages whose name, or a binary's built from them, contains " +
			"`q`, without regard to capitals, one entry per product and source package, in the builds " +
			"the selection covers. An exact name comes first, then by name.\n\n" +
			"Each entry counts what is open on it in both families where you read them: `issues` where " +
			"you read dependency findings in the product, `code_findings` where you read security " +
			"testing material there. A product you read nothing in is not searched.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		core.ScopeQuery
		Term  string `query:"q" minLength:"1" maxLength:"200" required:"true" doc:"Part of a name"`
		Limit int    `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number of entries returned"`
	}) (*core.ListOutput[ComponentMatchBody], error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		scope, err := core.Scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		store := finding.NewStore(in.DB.DB)
		matches, err := store.Matching(ctx, subject, scope, strings.TrimSpace(input.Term), input.Limit)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "the components could not be searched")
		}
		issues, err := store.OpenIssuesOf(ctx, subject, matches)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "what is open on the components could not be counted", err)
		}
		code, err := analysis.OpenOfMatches(ctx, in.DB.DB, subject, matches)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the code findings on the components could not be counted", err)
		}
		out := &core.ListOutput[ComponentMatchBody]{}
		out.Body.Items = make([]ComponentMatchBody, 0, len(matches))
		for i, m := range matches {
			row := ComponentMatchBody{Product: m.Product, Component: m.Source}
			if n, ok := issues[i]; ok {
				row.Issues = &n
			}
			if n, ok := code[i]; ok {
				row.CodeFindings = &n
			}
			out.Body.Items = append(out.Body.Items, row)
		}
		return out, nil
	})
}
