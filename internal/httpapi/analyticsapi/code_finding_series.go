// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// CodeFindingSeriesBody is how many code findings one analyzer series holds, by state.
type CodeFindingSeriesBody struct {
	Series  string         `json:"series" doc:"The series' name, as its producer first sent it"`
	States  map[string]int `json:"states" doc:"The series' code findings by where they stand, every state named. A code finding on two builds in two states counts in both"`
	Waiting int            `json:"waiting" doc:"Open code findings a decision waiting for a second person leaves out of the queue, counted among the open in states"`
	Ruled   int            `json:"ruled" doc:"Dismissed code findings an approved suppression rule covers, counted among the dismissed in states"`
}

func registerCodeFindingSeries(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-code-finding-series", Method: http.MethodGet,
		Path:    "/v1/products/{product}/code-finding-series",
		Summary: "Count code findings by analyzer series",
		Description: "Returns one entry per analyzer series the product holds, ordered by name, " +
			"with how many of its code findings stand in each state across every build of the product. " +
			"A series with no code findings is listed with every count zero.\n\n" +
			"Each count is the total the code finding list answers for the same `series` and `state`.\n\n" +
			"Refused, with no count, to anybody who does not read security testing material in the product.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, "Requires security-testing-read on the product."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
	}) (*struct {
		Body struct {
			Items []CodeFindingSeriesBody `json:"items"`
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
			return nil, core.Refused(in.Logger, err, "cannot count the code findings")
		}
		out := &struct {
			Body struct {
				Items []CodeFindingSeriesBody `json:"items"`
			}
		}{}
		out.Body.Items = make([]CodeFindingSeriesBody, 0, len(counted))
		for _, each := range counted {
			out.Body.Items = append(out.Body.Items, seriesBody(each))
		}
		return out, nil
	})
}

// ComponentCodeFindingsBody is how many code findings a product places on one
// source package.
type ComponentCodeFindingsBody struct {
	Series []ComponentSeriesBody `json:"series" doc:"Every analyzer series of the product, ordered by name, with the code findings it holds on the source package in each state across every build"`
	Builds []ComponentBuildBody  `json:"builds" doc:"The open code findings on the source package per build and source version, where any are open"`
}

// ComponentSeriesBody is one analyzer series' code findings on a source
// package.
type ComponentSeriesBody struct {
	CodeFindingSeriesBody
	Unplaced int `json:"unplaced" doc:"Open code findings counted here that are placed on the build itself, because their files are in no repository a component of the build was built from. Only a build's own root holds them"`
}

// ComponentBuildBody is the open code findings one build places on a source
// package at one version.
type ComponentBuildBody struct {
	BranchOrTag string `json:"branch_or_tag"`
	Variant     string `json:"variant"`
	Version     string `json:"version" doc:"The version the source package was built at, as the component's entries name it"`
	Open        int    `json:"open" doc:"Open code findings, the ones a decision waits on included: the code finding list's open count for this component, version, branch or tag and variant"`
}

func registerComponentCodeFindings(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "count-component-code-findings", Method: http.MethodGet,
		Path:    "/v1/products/{product}/components/{component}/code-finding-counts",
		Summary: "Count a component's code findings",
		Description: "Returns the code findings the product places on one source package: per analyzer " +
			"series and state across every build, and the open ones per build and source version.\n\n" +
			"`component` is a binary name or a source package name a build of the product ships, matched " +
			"without regard to capitals, as the component page reads it. Each count is the total the code " +
			"finding list answers for the same `component`, `series` and `state`.\n\n" +
			"`unplaced` counts the open code findings placed on the build itself: on a name that is a " +
			"build's root, those on every root the build has had, and zero on any other name.\n\n" +
			"Refused, with no count, to anybody who does not read security testing material in the product.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, "Requires security-testing-read on the product."), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Component string `path:"component" maxLength:"200"`
	}) (*struct{ Body ComponentCodeFindingsBody }, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		scope, err := core.Scoped(ctx, in, subject, core.ScopeQuery{Product: input.Product})
		if err != nil {
			return nil, err
		}
		counted, err := analysis.CountsOfComponent(ctx, in.DB.DB, subject, analysis.Scope{
			ProductID: *scope.ProductID, Component: strings.TrimSpace(input.Component),
		})
		if err != nil {
			return nil, core.Refused(in.Logger, err, "cannot count the component's code findings")
		}
		out := &struct{ Body ComponentCodeFindingsBody }{}
		out.Body.Series = make([]ComponentSeriesBody, 0, len(counted.Series))
		for _, each := range counted.Series {
			out.Body.Series = append(out.Body.Series, ComponentSeriesBody{
				CodeFindingSeriesBody: seriesBody(each), Unplaced: each.Unplaced,
			})
		}
		out.Body.Builds = make([]ComponentBuildBody, 0, len(counted.Builds))
		for _, each := range counted.Builds {
			out.Body.Builds = append(out.Body.Builds, ComponentBuildBody{
				BranchOrTag: each.BranchOrTag, Variant: each.Variant, Version: each.Version, Open: each.Open,
			})
		}
		return out, nil
	})
}

// seriesBody is one series' counts as an answer states them.
func seriesBody(each analysis.SeriesCount) CodeFindingSeriesBody {
	states := make(map[string]int, len(each.ByState))
	for state, n := range each.ByState {
		states[string(state)] = n
	}
	return CodeFindingSeriesBody{Series: each.Series, States: states, Waiting: each.Waiting, Ruled: each.Ruled}
}
