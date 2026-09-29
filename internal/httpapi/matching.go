// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// UnmatchedBody is one component the scanner has no way to match.
type UnmatchedBody struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Purl      string `json:"purl,omitempty" doc:"The package identifier the scanner is given, where there is one"`
	CPE       string `json:"cpe,omitempty" doc:"The platform enumeration the scanner is given, where there is one"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"The kind of package this is, as its identifier spells it"`
	Namespace string `json:"namespace,omitempty" doc:"The namespace its package identifier names, where it names one"`
	Reason    string `json:"reason" enum:"no-identifier,unpublished-kind,no-version,no-distribution,generic-without-cpe" doc:"Why the scanner cannot match it. no-identifier: no package identifier, and a CPE alone matches nothing. unpublished-kind: a package type no vulnerability data is published against, such as a container image or a source repository. no-version: no version, or one reading unknown. no-distribution: a distribution's package that does not name the distribution release it was built for. generic-without-cpe: a generic package with no CPE"`
}

// ReasonCountBody is how many of a build's components one reason covers.
type ReasonCountBody struct {
	Reason string `json:"reason" enum:"no-identifier,unpublished-kind,no-version,no-distribution,generic-without-cpe" doc:"Why the scanner cannot match them"`
	Count  int    `json:"count" doc:"The number of the build's components it covers"`
}

// MatchCoverageBody is what a build holds that the scanner cannot match.
type MatchCoverageBody struct {
	Components int               `json:"components" doc:"The number of components the build holds"`
	Unmatched  int               `json:"unmatched" doc:"The number of those the scanner has no way to match"`
	Reasons    []ReasonCountBody `json:"reasons" doc:"Every reason with how many components it covers, zero included, in the order a component is tested against them. A component is counted under the first reason it meets"`
	Items      []UnmatchedBody   `json:"items" doc:"The unmatched components, narrowed by reason where one was asked for, ordered by reason and then by name"`
	Total      int               `json:"total" doc:"The number of items across every page"`
}

type matchCoverageOutput struct {
	Body MatchCoverageBody
}

// unmatchedIn reads what one build holds that the scanner cannot match, and
// how much it holds in all.
func unmatchedIn(ctx context.Context, in Deps, product, stream, variant string) ([]graph.Unmatched, int, error) {
	subject, target, err := browsing(ctx, in, product, stream, variant)
	if err != nil {
		return nil, 0, err
	}
	listed, held, err := graph.NewStore(in.DB.DB).Unmatched(ctx, subject, target)
	switch {
	case errors.Is(err, access.ErrDenied):
		return nil, 0, nothingScannedThere()
	case err != nil:
		return nil, 0, wentWrong(in.Logger, "what the scanner cannot match could not be read", err)
	}
	return listed, held, nil
}

// onlyReason narrows the unmatched to one reason, or leaves them where none
// was asked for.
func onlyReason(listed []graph.Unmatched, reason string) []graph.Unmatched {
	if reason == "" {
		return listed
	}
	var out []graph.Unmatched
	for _, one := range listed {
		if string(one.Reason) == reason {
			out = append(out, one)
		}
	}
	return out
}

// registerMatchCoverage answers what a build holds that the scanner has no way
// to match (REQ-79).
func registerMatchCoverage(api huma.API, in Deps) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-match-coverage", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/match-coverage",
		Summary: "List the components a scanner cannot match",
		Description: "Returns the components the build holds now that the vulnerability scanner " +
			"has no way to match, with the reason for each and a count per reason. Such a " +
			"component reports no findings whatever it contains.\n\n" +
			"Read from the component as the scanner is given it, when this is asked. A component " +
			"meeting several reasons is listed under the first in the order `reasons` gives.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Reason  string `query:"reason" enum:"no-identifier,unpublished-kind,no-version,no-distribution,generic-without-cpe" doc:"One reason alone"`
		Limit   int    `query:"limit" default:"200" minimum:"1" maximum:"500" doc:"The number returned"`
		Offset  int    `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*matchCoverageOutput, error) {
		listed, held, err := unmatchedIn(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		out := &matchCoverageOutput{}
		out.Body.Components, out.Body.Unmatched = held, len(listed)
		counts := map[graph.Unmatchable]int{}
		for _, one := range listed {
			counts[one.Reason]++
		}
		for _, reason := range graph.Reasons {
			out.Body.Reasons = append(out.Body.Reasons,
				ReasonCountBody{Reason: string(reason), Count: counts[reason]})
		}
		narrowed := onlyReason(listed, input.Reason)
		out.Body.Total = len(narrowed)
		out.Body.Items = []UnmatchedBody{}
		for _, one := range narrowed[min(input.Offset, len(narrowed)):min(input.Offset+input.Limit, len(narrowed))] {
			out.Body.Items = append(out.Body.Items, UnmatchedBody{
				Name: one.Name, Version: one.Version, Purl: one.Purl, CPE: one.CPE,
				Ecosystem: graph.EcosystemOf(one.Purl), Namespace: graph.NamespaceOf(one.Purl),
				Reason: string(one.Reason),
			})
		}
		return out, nil
	})
}

// registerMatchCoverageExport writes out what a build holds that the scanner
// cannot match, whole rather than a page of it.
func registerMatchCoverageExport(api huma.API, in Deps) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-match-coverage", Method: http.MethodGet,
		Path:    "/v1/products/{product}/streams/{stream}/variants/{variant}/match-coverage.{format}",
		Summary: "Export the components a scanner cannot match",
		Description: "Every component the match coverage list names, as a file, in the same order, " +
			"with the reason for each.",
		Tags: []string{"Findings"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Format  string `path:"format" enum:"csv,json"`
		Reason  string `query:"reason" enum:"no-identifier,unpublished-kind,no-version,no-distribution,generic-without-cpe" doc:"One reason alone"`
	}) (*huma.StreamResponse, error) {
		// Worked out whole before the response starts, so a build out of reach
		// is refused with a status rather than a file cut short. It is bounded
		// by what one build holds now.
		listed, _, err := unmatchedIn(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		narrowed := onlyReason(listed, input.Reason)
		out := Exporting{
			What: "components a scanner cannot match",
			About: []Stated{
				{"build", input.Product + " " + input.Stream + " (" + input.Variant + ")"},
				{"reason", input.Reason},
			},
			Header: []string{"reason", "name", "version", "purl", "cpe"},
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				if offset > 0 {
					return nil, nil
				}
				rows := make([][]string, 0, len(narrowed))
				for _, one := range narrowed {
					rows = append(rows, []string{string(one.Reason), one.Name, one.Version, one.Purl, one.CPE})
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, "match-coverage-"+downloadName(input.Product), out)
		}}, nil
	})
}
