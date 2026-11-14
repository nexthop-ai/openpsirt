// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

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
			"Below the findings come every open static analysis code finding of the same branch or tag " +
			"and variant, in the code finding queue's order, where you read them, those a decision waits on " +
			"included and those open only in releases past their end of life left out: `code finding` is " +
			"true on those " +
			"rows, and `path`, `line`, `function` and `message` say where each is and what the " +
			"analyzer said, and `component` and `version` name the component it is placed on, empty where " +
			"it is the build itself. No row carries source text. The filters ask what a code finding mostly " +
			"does not carry, a rating, an upstream or a decision, so a file narrowed by any filter but the " +
			"order holds no code finding, and says so. Three filters narrow no code finding and keep them: `below_minimum_severity`, `planned=unplanned`, " +
			"and `on=branch` with `support=in-support`, which is what the list reads when " +
			"neither is asked.\n\n" +
			"Takes every filter the findings list takes.\n\n" + core.ExportsBusy,
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product     string `path:"product"`
		Format      string `path:"format" enum:"csv,json"`
		BranchOrTag string `query:"branch_or_tag"`
		Variant     string `query:"variant"`
		core.AtOneBuild
		core.Narrowing
	}) (*huma.StreamResponse, error) {
		in := core.Of(ctx, in)
		at, err := core.ListNarrowed(ctx, in, core.ScopeQuery{
			Product: input.Product, BranchOrTag: input.BranchOrTag, Variant: input.Variant,
		}, input.AtOneBuild, input.Narrowing, "the minimum severity could not be read")
		if err != nil {
			return nil, err
		}
		subject, scope, floor, narrowed := at.Subject, at.Scope, at.MinimumSeverity, at.Filter

		findings := func(ctx context.Context, db bun.IDB, moment time.Time, limit, offset int) ([][]string, error) {
			groups, _, err := finding.NewStore(db).At(moment).Groups(ctx, subject, scope, limit, offset, narrowed)
			if err != nil {
				return nil, err
			}
			rows := make([][]string, 0, len(groups))
			for _, g := range groups {
				rows = append(rows, findingCells(g))
			}
			return rows, nil
		}
		parts, codeFindings := []core.Paged{findings}, withCodeFindings(input.Narrowing, input.AtOneBuild)
		if codeFindings.Value == codeFindingsListed {
			parts = append(parts, codeFindingRows(subject, analysis.Scope{
				ProductID: *scope.ProductID, BranchOrTagID: scope.BranchOrTagID, VariantID: scope.VariantID,
			}, ""))
		}
		return core.Export(in, input.Format, "findings-"+strings.ToLower(input.Product), core.Exporting{
			What:   "findings",
			About:  []core.Stated{core.TriagedAtOrAbove(floor), codeFindings},
			Header: findingColumns(),
			Rows:   core.InTurn(parts...),
		})
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
// The minimum severity is per product here, so the file cannot name one. It
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
			"Each product applies its own minimum severity, so the file states that rather than " +
			"naming one, and `product` is a column.\n\n" +
			"Below the findings come the open static analysis code findings of every product, by " +
			"product name, as the product export writes them. The columns and the rule about " +
			"filters are the product export's.\n\n" +
			"Takes every filter the cross-product list takes. `beneath` and `differs` are " +
			"not offered here, for the reason that list gives.\n\n" + core.ExportsBusy,
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Format string `path:"format" enum:"csv,json"`
		core.Narrowing
	}) (*huma.StreamResponse, error) {
		in := core.Of(ctx, in)
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		// The same handling the cross-product list gives severity: the line is
		// applied per row inside the store, and asking for it as a filter as
		// well would narrow twice and answer neither question.
		narrowed, err := input.Filter(finding.MinimumSeverity{Word: string(input.Severity)})
		if err != nil {
			return nil, err
		}
		narrowed.MinSeverity = ""
		findings := func(ctx context.Context, db bun.IDB, moment time.Time, limit, offset int) ([][]string, error) {
			groups, _, err := finding.NewStore(db).At(moment).Anywhere(ctx, subject, limit, offset, narrowed)
			if err != nil {
				return nil, err
			}
			rows := make([][]string, 0, len(groups))
			for _, g := range groups {
				rows = append(rows, append([]string{g.Product}, findingCells(g)...))
			}
			return rows, nil
		}
		parts, codeFindings := []core.Paged{findings}, withCodeFindings(input.Narrowing, core.AtOneBuild{})
		if codeFindings.Value == codeFindingsListed {
			parts = append(parts, everyProductsCodeFindings(subject))
		}
		return core.Export(in, input.Format, "findings", core.Exporting{
			What:   "findings, every product",
			About:  []core.Stated{core.TriagedEachAtItsOwn(), codeFindings},
			Header: append([]string{"product"}, findingColumns()...),
			Rows:   core.InTurn(parts...),
		})
	})
}

// everyProductsCodeFindings is the open code findings of every product the
// subject reads, one product after another by name.
//
// The products are read on the first page asked, through the handle that page
// is read through, so a product's name on its code findings is the name its
// findings carry: read before the file's snapshot, a rename in between names
// one product two ways in one file.
func everyProductsCodeFindings(subject access.Subject) core.Paged {
	var each core.Paged
	return func(ctx context.Context, db bun.IDB, moment time.Time, limit, offset int) ([][]string, error) {
		if each == nil {
			products, err := catalog.NewStore(db).Products(ctx, subject)
			if err != nil {
				return nil, err
			}
			parts := make([]core.Paged, 0, len(products))
			for _, p := range products {
				if _, err := access.Readable(subject, p.ID); err == nil {
					parts = append(parts, codeFindingRows(subject, analysis.Scope{ProductID: p.ID}, p.Name))
				}
			}
			each = core.InTurn(parts...)
		}
		return each(ctx, db, moment, limit, offset)
	}
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
//
// A code finding is a row of the same columns. The columns after the variant are a
// code finding's, and empty on every other row; the columns before it that a code finding
// carries nothing for are empty on a code finding's.
func findingColumns() []string {
	return []string{
		"issue", "severity", "score", "score scheme", "exploited", "component", "version",
		"ecosystem", "upstream fix", "packages", "consumers", "state", "opened", "due",
		"branch_or_tag", "variant", "code finding", "path", "line", "function", "message",
	}
}

// findingCells is one row of a findings export.
func findingCells(g finding.Group) []string {
	due, opened := "", ""
	if g.DueAt != nil {
		due = g.DueAt.UTC().Format("2006-01-02")
	} else if g.NoDeadline != "" {
		due = string(g.NoDeadline)
	}
	if !g.OpenedAt.IsZero() {
		opened = g.OpenedAt.UTC().Format("2006-01-02")
	}
	return []string{
		g.Vulnerability, g.Severity, scoreCell(g.Scored, g.ScoreCenti),
		g.ScoreVersion, strconv.FormatBool(g.Exploited),
		g.Component, g.Version, g.Ecosystem, g.FixedIn,
		strconv.Itoa(g.Packages), strconv.Itoa(g.Consumers),
		string(g.State), opened, due,
		g.BranchOrTag, g.Variant, "false", "", "", "", "",
	}
}

// codeFindingsListed is what a findings file says about its code findings where it holds
// them.
const codeFindingsListed = "every open code finding, below the findings, those a decision waits on included and those open only in releases past their end of life left out"

// withCodeFindings is the fact a findings file states about the code findings it holds. A
// narrowing is the findings list's, asked of what a code finding mostly does not carry: a
// rating, an upstream, a decision or a deadline. So a narrowing asking anything but the
// order matches none, and the file says so rather than leaving a reader to wonder where
// the code findings went.
func withCodeFindings(by core.Narrowing, at core.AtOneBuild) core.Stated {
	switch {
	case !kind.Exports.Includes(kind.Analysis):
		return core.Stated{}
	case !by.OnlyOrders() || at != (core.AtOneBuild{}):
		return core.Stated{Label: "code findings", Value: "none: a filter asks what a code finding does not carry"}
	}
	return core.Stated{Label: "code findings", Value: codeFindingsListed}
}

// codeFindingRows is the open code findings of one product in a selection, as findings file
// rows, with the product's name in front where the file spans products.
//
// The code finding queue's read, under its visibility, with the code findings a decision
// waits on kept in. No row carries source text. A product whose code findings the reader may not read is a part holding
// no row.
func codeFindingRows(subject access.Subject, scope analysis.Scope, product string) core.Paged {
	return func(ctx context.Context, db bun.IDB, moment time.Time, limit, offset int) ([][]string, error) {
		open, err := analysis.OpenCodeFindingsOf(ctx, db, subject, scope, moment, limit, offset)
		if errors.Is(err, access.ErrDenied) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		rows := make([][]string, 0, len(open))
		for _, r := range open {
			cells := codeFindingCells(r)
			if product != "" {
				cells = append([]string{product}, cells...)
			}
			rows = append(rows, cells)
		}
		return rows, nil
	}
}

// codeFindingCells is one code finding as a row of a findings file. The rule is the issue,
// and the component it is placed on fills the component and version, empty where it is the
// build itself. A line the analyzer named none for is an empty cell, never a zero.
func codeFindingCells(r analysis.QueueRow) []string {
	line := ""
	if r.Line != nil {
		line = strconv.Itoa(*r.Line)
	}
	component, version := r.Component, r.Version
	if r.OnBuild {
		component, version = "", ""
	}
	return []string{
		r.Rule, "", "", "", "", component, version, "", "", "", "", "", r.Opened.UTC().Format(time.DateOnly), "",
		r.BranchOrTag, r.Variant, "true", r.Path, line, r.Function, r.Message,
	}
}
