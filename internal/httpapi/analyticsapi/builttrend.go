// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// BuiltTrendQuery is what a trend by build date is asked with: the scope, the
// step, how many points, and the trend's narrowings.
type BuiltTrendQuery struct {
	core.ScopeQuery
	Weekly    bool   `query:"weekly" doc:"Whether build times are grouped by week rather than by day"`
	Limit     int    `query:"limit" default:"12" minimum:"1" maximum:"50" doc:"The number of points, most recent kept. Only steps holding a build time are points"`
	Component string `query:"component" doc:"Keep only what is open against components of this name, whatever version"`
	Purl      string `query:"purl" doc:"Keep only what is open against components whose package identifier this prefix chooses, whatever version and qualifiers: a package such as pkg:github/sonic-net/sonic-swss, or everything under a path ending in a slash such as pkg:github/sonic-net/. Without the slash it is that package alone. Matched without regard to capitals. A prefix that does not start with pkg: and a type is refused"`
	core.Subtree
}

func registerBuiltTrend(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-built-trend", Method: http.MethodGet, Path: "/v1/trend/built",
		Summary: "Show the findings trend by build date",
		Description: "Returns the findings trend with each point at a build date: one point per " +
			"day or week holding the build time an upload in the selection states, oldest first, " +
			"each dated by its step's last day. Steps end at midnight UTC, as on the findings trend.\n\n" +
			"At a point, each build counts as its newest upload built by then leaves it. The " +
			"upload a build holds is counted now. A replaced one is counted as of the last scan " +
			"of its build that started while it was current, never against today's vulnerability " +
			"data. An upload no scan reached before it was replaced is passed over.\n\n" +
			"Counted as the findings trend counts: one issue in three packages is three, and a " +
			"package at a new version is the same package. Flows compare a point with the one " +
			"before: `new` is open now and at no earlier point; `returned` is open now, not at " +
			"the point before, and at an earlier one; `corrected` was open at the point before, " +
			"is not now, and left by a fix; what a build's first upload brought is `baseline`, " +
			"and `first_scans` says how many builds' first uploads the point is. The first point " +
			"has nothing before it, so only its baseline moves. `restored` is always zero.\n\n" +
			"`component`, `purl` and `beneath` narrow as on the findings trend.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		BuiltTrendQuery
	}) (*core.ListOutput[PointBody], error) {
		in := core.Of(ctx, in)
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		q := input.BuiltTrendQuery
		// The scope first, so a product somebody may not see answers as one
		// nobody declared, whatever else the request lacks.
		scope, err := core.Scoped(ctx, in, subject, q.ScopeQuery)
		if err != nil {
			return nil, err
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
		step := 24 * time.Hour
		if q.Weekly {
			step *= 7
		}
		points, err := ingest.NewStore(in.DB.DB).BuiltTrend(ctx, subject, scope,
			finding.Within{Component: q.Component, Purl: prefix, Beneath: beneath}, step, q.Limit)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "the trend by build date could not be worked out")
		}
		out := &core.ListOutput[PointBody]{}
		out.Body.Items = make([]PointBody, 0, len(points))
		for _, p := range points {
			out.Body.Items = append(out.Body.Items, pointBody(p))
		}
		return out, nil
	})
}
