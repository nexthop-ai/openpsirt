// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// streamSlots bounds how many streamed exports hold a connection at once.
//
// A fifth of the pool, and at least one: the rest of the pool is left for
// every other request. A pool of one connection has one slot, and it is the
// whole of the pool for as long as the stream runs, which exportCeiling
// bounds.
type streamSlots chan struct{}

// exportStreams is the number of slots where the pool states no size.
const exportStreams = 5

func newStreamSlots(db *database.DB) streamSlots {
	n := exportStreams
	if db != nil {
		if open := db.DB.DB.Stats().MaxOpenConnections; open > 0 {
			n = max(1, open/5)
		}
	}
	return make(streamSlots, n)
}

// take claims a slot, or refuses with a time to ask again. The release is
// called once the stream has finished writing.
func (s streamSlots) take() (func(), error) {
	select {
	case s <- struct{}{}:
		return func() { <-s }, nil
	default:
		return nil, huma.ErrorWithHeaders(
			huma.Error503ServiceUnavailable("too many exports are being written at once; ask again shortly"),
			http.Header{"Retry-After": []string{"30"}})
	}
}

// scoreCell is a severity score as a file states it, and nothing where there
// is none.
//
// Written as a zero, an unscored finding sorts with the genuinely 0.0-rated
// ones at the bottom of a release meeting's spreadsheet, and a filter for
// "below four" takes every one of them. Empty is the only thing a column of
// numbers has for "there is no number".
func scoreCell(scored bool, centi int) string {
	if !scored {
		return ""
	}
	return strconv.FormatFloat(float64(centi)/100, 'f', -1, 64)
}

func registerExport(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-findings", Method: http.MethodGet,
		Path:    "/v1/products/{product}/findings.{format}",
		Summary: "Export the findings list",
		Description: "The findings list as a file: every row the same filters would show, not " +
			"one page of them.\n\n" +
			"Read with your own visibility, as it streams. It is the same query the screen " +
			"reads, paged and written out as it goes.\n\n" +
			"The line this deployment triages at is stated in the file.\n\n" +
			"Takes every filter the findings list takes.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Format  string `path:"format" enum:"csv,json"`
		Stream  string `query:"stream"`
		Variant string `query:"variant"`
		core.AtOneBuild
		core.Narrowing
	}) (*huma.StreamResponse, error) {
		at, err := core.ListNarrowed(ctx, in, core.ScopeQuery{
			Product: input.Product, Stream: input.Stream, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "the triage line could not be read")
		if err != nil {
			return nil, err
		}
		subject, scope, floor, narrowed, store := at.Subject, at.Scope, at.Floor, at.Filter, at.Store

		line := "everything"
		if floor.Hides() {
			line = floor.Word
		}
		out := core.Exporting{
			What:   "findings",
			About:  []core.Stated{{Label: "triaged at or above", Value: line}},
			Header: findingColumns(),
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				groups, _, err := store.Groups(ctx, subject, scope, limit, offset, narrowed)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(groups))
				for _, g := range groups {
					rows = append(rows, findingCells(g))
				}
				return rows, nil
			},
		}
		name := "findings-" + strings.ToLower(input.Product)
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, name, out)
		}}, nil
	})
}

// registerAnywhereExport is the cross-product findings list as a file.
//
// The same query the cross-product list reads, paged and written as it goes,
// with the product as a column because it is the thing that varies. Without
// it, the one screen covering the whole estate is the one screen whose answer
// cannot leave the application — which is the screen somebody reporting to a
// manager is on.
//
// The triage line is per product here, so the file cannot name one. It
// says so rather than naming a number that would be wrong for every product
// but one.
func registerAnywhereExport(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "export-findings-anywhere", Method: http.MethodGet,
		Path:    "/v1/findings.{format}",
		Summary: "Export findings across every product",
		Description: "The cross-product findings list as a file: every row the same filters " +
			"would show, not one page of them.\n\n" +
			"Read with your own visibility, as it streams. It is the same query the " +
			"screen reads, paged and written out as it goes.\n\n" +
			"Each product applies its own triage line, so the file states that rather than " +
			"naming one line, and `product` is a column.\n\n" +
			"Takes every filter the cross-product list takes. `beneath` and `differs` are " +
			"not offered here, for the reason that list gives.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		core.Narrowing
	}) (*huma.StreamResponse, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}
		// The same handling the cross-product list gives severity: the line is
		// applied per row inside the store, and asking for it as a filter as
		// well would narrow twice and answer neither question.
		narrowed, err := input.Filter(finding.Floor{Word: string(input.Severity)})
		if err != nil {
			return nil, err
		}
		narrowed.MinSeverity = ""
		store := finding.NewStore(in.DB.DB)
		out := core.Exporting{
			What:   "findings, every product",
			About:  []core.Stated{{Label: "triaged at or above", Value: "each product's own line"}},
			Header: append([]string{"product"}, findingColumns()...),
			Rows: func(ctx context.Context, limit, offset int) ([][]string, error) {
				groups, _, err := store.Anywhere(ctx, subject, limit, offset, narrowed)
				if err != nil {
					return nil, err
				}
				rows := make([][]string, 0, len(groups))
				for _, g := range groups {
					rows = append(rows, append([]string{g.Product}, findingCells(g)...))
				}
				return rows, nil
			},
		}
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			core.WriteExport(writer, input.Format, "findings", out)
		}}, nil
	})
}

// findingColumns names the columns of a findings export, in the order
// findingCells fills them.
//
// One list for the export within a product and the one across products, which
// adds the product in front: two lists is how the same export comes to carry
// different columns depending on where it was asked for. The scheme sits
// beside the score because two schemes are scorable and their numbers are not
// comparable, so a column of them read by somebody's script is a ranking that
// is not one.
func findingColumns() []string {
	return []string{
		"issue", "severity", "score", "score scheme", "exploited", "component", "version",
		"ecosystem", "upstream fix", "packages", "consumers", "state", "opened", "due",
		"stream", "variant",
	}
}

// findingCells is one row of a findings export.
func findingCells(g finding.Group) []string {
	due, opened := "", ""
	if g.DueAt != nil {
		due = g.DueAt.Format("2006-01-02")
	} else if g.NoDeadline != "" {
		due = string(g.NoDeadline)
	}
	if !g.OpenedAt.IsZero() {
		opened = g.OpenedAt.Format("2006-01-02")
	}
	return []string{
		g.Vulnerability, g.Severity, scoreCell(g.Scored, g.ScoreCenti),
		g.ScoreVersion, strconv.FormatBool(g.Exploited),
		g.Component, g.Version, g.Ecosystem, g.FixedIn,
		strconv.Itoa(g.Packages), strconv.Itoa(g.Consumers),
		string(g.State), opened, due,
		g.Stream, g.Variant,
	}
}
