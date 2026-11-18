// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// UploadPointBody is one upload of a build, at the build time it states.
type UploadPointBody struct {
	ScanID     int64          `json:"scan_id" doc:"The scan this upload became, as its receipt names it"`
	BuiltAt    string         `json:"built_at" format:"date-time" doc:"The build time the inventory states, which places the point"`
	AsOf       string         `json:"as_of" format:"date-time" doc:"The moment counted: the start of the last scan of the build while this inventory was current, or now for the inventory the build holds"`
	Current    bool           `json:"current" doc:"Whether the build holds this inventory now. A replaced one is counted as of its last scan, never against today's vulnerability data"`
	Open       int            `json:"open" doc:"Issues at components open at that moment"`
	BySeverity map[string]int `json:"by_severity" doc:"Open, split by severity"`
}

// UploadTrendQuery is what a build trend is asked with: the one build, how
// many uploads, and the trend's narrowings.
type UploadTrendQuery struct {
	core.ScopeQuery
	Limit     int    `query:"limit" default:"12" minimum:"1" maximum:"50" doc:"The number of uploads, most recent kept"`
	Component string `query:"component" doc:"Keep only what is open against components of this name, whatever version"`
	Purl      string `query:"purl" doc:"Keep only what is open against components whose package identifier this prefix chooses, whatever version and qualifiers: a package such as pkg:github/sonic-net/sonic-swss, or everything under a path ending in a slash such as pkg:github/sonic-net/. Without the slash it is that package alone. Matched without regard to capitals. A prefix that does not start with pkg: and a type is refused"`
	core.Subtree
}

func registerUploadTrend(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-upload-trend", Method: http.MethodGet, Path: "/v1/trend/uploads",
		Summary: "Plot a build's exposure by build time",
		Description: "One point per upload of one build, oldest first, placed at the build time " +
			"its inventory states, with the issues at components open while it was current, " +
			"split by severity.\n\n" +
			"The inventory the build holds is counted now. A replaced one is counted as of the " +
			"last scan of the build that started while it was current, never against today's " +
			"vulnerability data; `as_of` says which moment. An upload no scan reached before it " +
			"was replaced is no point.\n\n" +
			"Counted as the findings trend counts: one issue in three packages is three, and a " +
			"package at a new version is the same package.\n\n" +
			"A product, a branch or tag, and a variant must be named, since the uploads are one " +
			"build's. `component`, `purl` and `beneath` narrow as on the findings trend.",
		Tags: []string{"Analytics"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		UploadTrendQuery
	}) (*core.ListOutput[UploadPointBody], error) {
		in := core.Of(ctx, in)
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		q := input.UploadTrendQuery
		// The scope first, so a product somebody may not see answers as one
		// nobody declared, whatever else the request lacks.
		scope, err := core.Scoped(ctx, in, subject, q.ScopeQuery)
		if err != nil {
			return nil, err
		}
		if q.Product == "" || q.BranchOrTag == "" || q.Variant == "" {
			return nil, huma.Error422UnprocessableEntity(
				"name a product, a branch or tag, and a variant: the uploads plotted are one build's")
		}
		var prefix graph.PurlPrefix
		if strings.TrimSpace(q.Purl) != "" {
			if prefix = graph.ParsePurlPrefix(q.Purl); prefix.Empty() {
				return nil, huma.Error422UnprocessableEntity(
					"purl is a package identifier prefix, such as pkg:github/sonic-net/ or pkg:deb/debian/curl")
			}
		}
		beneath, err := q.Starts(ctx, in, scope)
		if err != nil {
			return nil, err
		}
		points, err := ingest.NewStore(in.DB.DB).BuildTrend(ctx, subject, scope,
			finding.Within{Component: q.Component, Purl: prefix, Beneath: beneath}, q.Limit)
		switch {
		case errors.Is(err, finding.ErrNotOneBuild):
			return nil, huma.Error422UnprocessableEntity(
				"that product, branch or tag and variant name no build: send the three a build was declared with")
		case err != nil:
			return nil, core.Refused(in.Logger, err, "the build trend could not be worked out")
		}
		out := &core.ListOutput[UploadPointBody]{}
		out.Body.Items = make([]UploadPointBody, 0, len(points))
		for _, p := range points {
			out.Body.Items = append(out.Body.Items, UploadPointBody{
				ScanID: p.ScanID, BuiltAt: core.Stamp(p.BuiltAt), AsOf: core.Stamp(p.AsOf),
				Current: p.Current, Open: p.Open, BySeverity: p.BySeverity,
			})
		}
		return out, nil
	})
}
