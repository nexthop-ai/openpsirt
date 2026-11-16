// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ReleasePoint is one frozen point on a trend that follows releases.
//
// A tag never moves: what it shipped is what it shipped, and what is open
// against it is answered now against the vulnerability data of today rather
// than as of the day it was cut. That is the point of re-scanning a shipped
// release, and it is why this is a snapshot per release rather than a
// timeline.
type ReleasePoint struct {
	// BranchOrTag is the name a path addresses the release by, and BranchOrTagName the
	// spelling shown.
	BranchOrTag, BranchOrTagName string
	// Cut is when the release went out, where somebody said, and when it was
	// declared here otherwise. It is what orders them and it is not the axis:
	// the axis is the sequence, and the dates are labels.
	Cut time.Time
	// Open is the issues at components open against it, and BySeverity the
	// split. Counted in the calendar trend's unit, so the two charts on one
	// screen cannot be quoting different units for the same word.
	Open       int
	BySeverity map[string]int
}

// ErrNoProductNamed is what a question about one product's line of releases
// answers where no product was named.
//
// Its own answer rather than an empty list, because an empty list is what a
// product with no releases looks like and the two are not the same statement.
var ErrNoProductNamed = refusal.New("release over release is a question about one product")

// ReleaseTrend reports what is open against each tagged release of a product.
//
// The axis follows what is being viewed. A branch is scanned
// nightly and has continuous data, so a calendar reads correctly on it. A tag
// is one frozen point that never moves again, and releases months apart make a
// calendar count read as slow drift rather than the step change it was — the
// gaps between them are the chart's whole shape, and they are gaps in nothing.
//
// Rates are not offered here. How many appeared and were resolved between
// two releases is a different question from what each shipped with, and the
// answer would be an artifact of how far apart somebody cut them. Rates always
// plot on calendar.
func (s *Store) ReleaseTrend(ctx context.Context, subject access.Subject, scope Scope,
	limit int) ([]ReleasePoint, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing anywhere is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read how a release is trending")
	}
	// A named product this subject reads nothing in is refused rather than
	// drawn as a chart with nothing on it.
	if scope.ProductID != nil {
		if _, err := access.Readable(subject, *scope.ProductID); err != nil {
			return nil, err
		}
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}
	if scope.ProductID == nil {
		// Release over release is a question about one product's line of
		// releases. Across products there is no sequence to plot: two
		// products' tags interleave by date and mean nothing side by side.
		//
		// Refused rather than answered empty. An empty list is what a product
		// with no releases looks like, and a request naming no product is a
		// different answer: the route's own description says a product must
		// be named.
		return nil, ErrNoProductNamed
	}
	limit = database.APlot.Of(limit)

	var rows []struct {
		BranchOrTag     string    `bun:"branch_or_tag"`
		BranchOrTagName string    `bun:"branch_or_tag_name"`
		CreatedAt       time.Time `bun:"created_at"`
		Band            string    `bun:"band"`
		Vulnerability   int64     `bun:"vulnerability_id"`
		Folded          string    `bun:"name_folded"`
		Name            string    `bun:"name"`
		Version         string    `bun:"version"`
		Purl            string    `bun:"purl"`
	}
	// The issues at components per release, then the band of each, counted
	// here. A component is its identifying name, so one name at two versions
	// is one, and so are two versions of a package named after its version
	// (design-docs/data-model-components.md § The identifying name). The
	// pairs are reduced before the issue or its rating is joined: a release
	// holds each issue at many occurrences, and joining first reads the
	// issue's row once per occurrence only to fold the copies away. Inside one
	// product an issue has one band, so each is already distinct once it
	// carries one.
	kinds, kindArgs := kind.Statistics.Where(`"f"."kind"`)
	issues := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "b" ON "b"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
		ColumnExpr(`"b"."branch_or_tag_id" AS "branch_or_tag_id"`).
		Join(`JOIN "component" AS "rc" ON "rc"."id" = "f"."component_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"rc"."name_folded" AS "name_folded", MIN("rc"."name") AS "name"`).
		ColumnExpr(`MIN("rc"."version") AS "version", MIN(COALESCE("rc"."purl", '')) AS "purl"`).
		Where(`"st"."kind" = ?`, catalog.Tag).
		Where(`"f"."closed_at" IS NULL`).
		Where(kinds, kindArgs...).
		GroupExpr(`"b"."branch_or_tag_id", "f"."vulnerability_id", "rc"."name_folded"`)
	issues = scope.Narrow(onlyReadable(issues, subject, products, all))

	inner := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, issues).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "grouped"."branch_or_tag_id"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "grouped"."vulnerability_id"`).
		Join(rating.For(rating.OnBranchOrTag)).
		ColumnExpr(`"st"."name" AS "branch_or_tag"`).
		ColumnExpr(catalog.ShownExpr("st") + ` AS "branch_or_tag_name"`).
		// The day it went out, where somebody said, and the day it was declared
		// here otherwise. Ordered by the declaration alone, the chart is an
		// accident of administration: a release recorded months after it
		// shipped sorts after ones that came out later, and a year
		// backfilled in an afternoon plots as a single day.
		ColumnExpr(`COALESCE("st"."released_on", "st"."created_at") AS "created_at"`).
		ColumnExpr(rating.BandExpr + ` AS "band"`).
		ColumnExpr(`"grouped"."vulnerability_id", "grouped"."name_folded", "grouped"."name"`).
		ColumnExpr(`"grouped"."version", "grouped"."purl"`)

	if err := s.db.NewSelect().
		TableExpr(`(?) AS "per_release"`, inner).
		ColumnExpr(`"per_release"."branch_or_tag", "per_release"."branch_or_tag_name", "per_release"."created_at"`).
		ColumnExpr(`"per_release"."band", "per_release"."vulnerability_id", "per_release"."name_folded"`).
		ColumnExpr(`"per_release"."name", "per_release"."version", "per_release"."purl"`).
		// Newest last, so the chart reads left to right the way time does.
		OrderExpr(`"created_at", "branch_or_tag"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what each release shipped with: %w", err)
	}

	// Gathered in order, so the sequence is the order they were cut.
	type counted struct {
		branchOrTag, component string
		vulnerability          int64
	}
	seen := map[counted]bool{}
	var out []ReleasePoint
	at := map[string]int{}
	for _, row := range rows {
		one := counted{row.BranchOrTag, graph.IdentifyingFolded(row.Folded, row.Name, row.Version, row.Purl),
			row.Vulnerability}
		if seen[one] {
			continue
		}
		seen[one] = true
		i, held := at[row.BranchOrTag]
		if !held {
			out = append(out, ReleasePoint{
				BranchOrTag: row.BranchOrTag, BranchOrTagName: row.BranchOrTagName, Cut: row.CreatedAt,
				BySeverity: map[string]int{},
			})
			i = len(out) - 1
			at[row.BranchOrTag] = i
		}
		out[i].Open++
		out[i].BySeverity[row.Band]++
	}
	// The most recent, where there are more than a chart can carry. Taken from
	// the end because the releases somebody is comparing are the recent ones,
	// and a chart that dropped those to keep the oldest would be answering
	// about a version nobody runs.
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}
