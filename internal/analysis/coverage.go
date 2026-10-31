// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

// Analyzed is one series on one build in use: its newest applied run, its
// newest comparable one, the runs that arrived in a window, and its rhythm.
type Analyzed struct {
	// BranchOrTag and Variant name the build as an address does, and the
	// Shown ones as a person reads it.
	BranchOrTag, BranchOrTagShown string
	Variant, VariantShown         string
	Series                        string
	Method                        Method
	// PastEndOfLife is a release past its end of life, analyzed by nobody on
	// purpose: listed and marked, never quiet.
	PastEndOfLife bool
	// Arrived and Applied are when the newest applied run arrived and was
	// applied, nil where none was.
	Arrived, Applied *time.Time
	// NotComparable is why that run's absences are no evidence, empty where
	// they are.
	NotComparable series.Reason
	// UnitsExpected and UnitsAnalyzed are what that run said it was meant to
	// analyze and did, nil where it said nothing.
	UnitsExpected, UnitsAnalyzed *int
	// Comparable is when the newest comparable run arrived, nil where none
	// did.
	Comparable *time.Time
	// AppliedRuns, NotComparableRuns and FailedRuns are the runs that arrived
	// in the window: applied, applied and not comparable among them, and
	// failed.
	AppliedRuns, NotComparableRuns, FailedRuns int
	// Rhythm is the series' own expected interval on the build, the rule
	// the stopped-reporting alert reads, with the silence counted from the
	// newest comparable run: a series is quiet when no run its absences can
	// be trusted from arrived within its interval.
	Rhythm series.Rhythm
}

// Quiet is whether the series has gone quiet on the build: silent past its
// own expected interval, on a release still in support.
func (a Analyzed) Quiet() bool { return a.Rhythm.Quiet && !a.PastEndOfLife }

// CoverageOf is every series on every build in use in the scope, longest
// silent first: what was analyzed, when, how much of what was meant to be,
// which runs failed or could not be compared in [since, until), and which
// series have gone quiet.
//
// Each series is quiet when no comparable run arrived within its own
// expected interval on its build, the median of its newest gaps between
// applied runs, never against one deployment-wide window: a nightly series and a quarterly one are each quiet on their own
// terms. A build retired at any level is left out; a release past its end of
// life is listed and never quiet. Refused to anybody who does not read
// security testing material in the product. A series and its runs are about
// security testing work, so they carry the family's visibility and no other.
func CoverageOf(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	since, until, now time.Time) ([]Analyzed, error) {

	if err := MayCount(subject, scope.ProductID, "read the analysis coverage"); err != nil {
		return nil, err
	}
	named, namedArgs := kind.SecurityTestingStatistics.Where(`"se"."kind"`)
	runs := func() *bun.SelectQuery {
		q := db.NewSelect().TableExpr(`"series_run" AS "sr"`).
			Join(`JOIN "series" AS "se" ON "se"."id" = "sr"."series_id"`).
			Join(`JOIN "build" AS "t" ON "t"."id" = "sr"."build_id"`).
			Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
			Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
			Join(`JOIN "product" AS "p" ON "p"."id" = "se"."product_id"`).
			Where(`"se"."product_id" = ?`, scope.ProductID).
			Where(`"s"."product_id" = ?`, scope.ProductID).
			Where(named, namedArgs...).
			Where(`"s"."retired_at" IS NULL`).
			Where(`"va"."retired_at" IS NULL`).
			Where(`"p"."retired_at" IS NULL`)
		if scope.BranchOrTagID != nil {
			q = q.Where(`"t"."branch_or_tag_id" = ?`, *scope.BranchOrTagID)
		}
		if scope.VariantID != nil {
			q = q.Where(`"t"."variant_id" = ?`, *scope.VariantID)
		}
		if scope.Method != "" {
			q = q.Where(`"se"."kind" = ?`, methodKinds[scope.Method])
		}
		if scope.Series != "" {
			q = q.Where(`"se"."name_folded" = ?`, typedname.Matching(scope.Series))
		}
		return q
	}

	type pair struct{ series, build int64 }
	at := map[pair]*Analyzed{}
	arrived := map[pair][]time.Time{}
	var order []pair
	place := func(p pair, row seriesBuild) *Analyzed {
		one := at[p]
		if one == nil {
			one = &Analyzed{
				BranchOrTag: row.BranchOrTag, BranchOrTagShown: row.BranchOrTagShown,
				Variant: row.Variant, VariantShown: row.VariantShown,
				Series: row.Series, Method: methodOf(row.Kind),
			}
			at[p] = one
			order = append(order, p)
		}
		return one
	}
	withNames := func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.ColumnExpr(`"sr"."series_id", "sr"."build_id", "t"."branch_or_tag_id"`).
			ColumnExpr(`"s"."name" AS "branch_or_tag", ` + catalog.ShownExpr("s") + ` AS "branch_or_tag_shown"`).
			ColumnExpr(`"va"."name" AS "variant", ` + catalog.ShownExpr("va") + ` AS "variant_shown"`).
			ColumnExpr(`"se"."name" AS "series", "se"."kind"`)
	}

	// The newest applied runs of each series on each build, numbered newest
	// first, so the rhythm is read from the same few runs however long the
	// series has run, and the first is the newest run's own.
	var newest []struct {
		seriesBuild
		Arrived       time.Time     `bun:"received_at"`
		Applied       *time.Time    `bun:"applied_at"`
		NotComparable series.Reason `bun:"not_comparable"`
		Comparable    *bool         `bun:"comparable"`
		UnitsExpected *int          `bun:"units_expected"`
		UnitsAnalyzed *int          `bun:"units_analyzed"`
		Newest        int           `bun:"newest"`
	}
	if err := db.NewSelect().
		TableExpr(`(?) AS "ranked"`, withNames(runs()).
			ColumnExpr(`"sr"."received_at", "sr"."applied_at", "sr"."not_comparable", "sr"."comparable"`).
			ColumnExpr(`"sr"."units_expected", "sr"."units_analyzed"`).
			ColumnExpr(`ROW_NUMBER() OVER (PARTITION BY "sr"."series_id", "sr"."build_id" `+
				`ORDER BY "sr"."received_at" DESC, "sr"."id" DESC) AS "newest"`).
			Where(`"sr"."status" = ?`, series.Applied)).
		ColumnExpr(`"ranked".*`).
		Where(`"ranked"."newest" <= ?`, series.RhythmGaps+1).
		OrderExpr(`"ranked"."series_id", "ranked"."build_id", "ranked"."newest"`).
		Scan(ctx, &newest); err != nil {
		return nil, fmt.Errorf("read the newest analyzer runs of product %d: %w", scope.ProductID, err)
	}
	for _, row := range newest {
		p := pair{row.SeriesID, row.BuildID}
		one := place(p, row.seriesBuild)
		arrived[p] = append(arrived[p], row.Arrived.UTC())
		if row.Newest != 1 {
			continue
		}
		received := row.Arrived
		one.Arrived, one.Applied = &received, row.Applied
		if row.Comparable != nil && !*row.Comparable {
			one.NotComparable = row.NotComparable
		}
		one.UnitsExpected, one.UnitsAnalyzed = row.UnitsExpected, row.UnitsAnalyzed
	}

	// The newest comparable run, however far back it was, on the axis the
	// rhythm is read on.
	var comparable []struct {
		seriesBuild
		At time.Time `bun:"comparable_at"`
	}
	if err := withNames(runs()).
		ColumnExpr(`MAX("sr"."received_at") AS "comparable_at"`).
		Where(`"sr"."status" = ?`, series.Applied).
		Where(`"sr"."comparable" = TRUE`).
		GroupExpr(`"sr"."series_id", "sr"."build_id", "t"."branch_or_tag_id", "s"."name", "s"."display_name"`).
		GroupExpr(`"va"."name", "va"."display_name", "se"."name", "se"."kind"`).
		Scan(ctx, &comparable); err != nil {
		return nil, fmt.Errorf("read the newest comparable analyzer runs of product %d: %w", scope.ProductID, err)
	}
	for _, row := range comparable {
		received := row.At
		place(pair{row.SeriesID, row.BuildID}, row.seriesBuild).Comparable = &received
	}

	// The runs that arrived in the window, by what became of them. A series
	// whose every run failed is listed by these alone.
	var window []struct {
		seriesBuild
		Status     series.Status `bun:"status"`
		Comparable *bool         `bun:"comparable"`
		Runs       int           `bun:"runs"`
	}
	if err := withNames(runs()).
		ColumnExpr(`"sr"."status", "sr"."comparable", COUNT(*) AS "runs"`).
		Where(`"sr"."status" IN (?)`, bun.List([]series.Status{series.Applied, series.Failed})).
		Where(`"sr"."received_at" >= ?`, since).
		Where(`"sr"."received_at" < ?`, until).
		GroupExpr(`"sr"."series_id", "sr"."build_id", "t"."branch_or_tag_id", "s"."name", "s"."display_name"`).
		GroupExpr(`"va"."name", "va"."display_name", "se"."name", "se"."kind", "sr"."status", "sr"."comparable"`).
		Scan(ctx, &window); err != nil {
		return nil, fmt.Errorf("count the analyzer runs of product %d: %w", scope.ProductID, err)
	}
	for _, row := range window {
		one := place(pair{row.SeriesID, row.BuildID}, row.seriesBuild)
		switch row.Status {
		case series.Failed:
			one.FailedRuns += row.Runs
		case series.Applied:
			one.AppliedRuns += row.Runs
			if row.Comparable != nil && !*row.Comparable {
				one.NotComparableRuns += row.Runs
			}
		}
	}

	ended, err := catalog.NewStore(db).BranchesAndTagsPastEndOfLife(ctx, now)
	if err != nil {
		return nil, err
	}
	past := map[int64]bool{}
	for _, id := range ended {
		past[id] = true
	}
	branchOf := map[pair]int64{}
	for _, row := range newest {
		branchOf[pair{row.SeriesID, row.BuildID}] = row.BranchOrTagID
	}
	for _, row := range window {
		branchOf[pair{row.SeriesID, row.BuildID}] = row.BranchOrTagID
	}
	out := make([]Analyzed, 0, len(order))
	for _, p := range order {
		one := at[p]
		one.PastEndOfLife = past[branchOf[p]]
		one.Rhythm = series.RhythmOf(arrived[p], now)
		switch runs := arrived[p]; {
		case one.Comparable != nil:
			one.Rhythm = one.Rhythm.Since(*one.Comparable, now)
		case len(runs) > 0:
			// Never comparable: silent at least since the oldest run read.
			one.Rhythm = one.Rhythm.Since(runs[len(runs)-1], now)
		}
		out = append(out, *one)
	}
	// Quiet first, then the longest silent, then never applied.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Quiet() != b.Quiet() {
			return a.Quiet()
		}
		if (a.Arrived == nil) != (b.Arrived == nil) {
			return a.Arrived != nil
		}
		if a.Arrived != nil && !a.Arrived.Equal(*b.Arrived) {
			return a.Arrived.Before(*b.Arrived)
		}
		if a.BranchOrTag != b.BranchOrTag {
			return a.BranchOrTag < b.BranchOrTag
		}
		if a.Variant != b.Variant {
			return a.Variant < b.Variant
		}
		return a.Series < b.Series
	})
	return out, nil
}

// seriesBuild is one series on one build, with the names a row needs.
type seriesBuild struct {
	SeriesID         int64     `bun:"series_id"`
	BuildID          int64     `bun:"build_id"`
	BranchOrTagID    int64     `bun:"branch_or_tag_id"`
	BranchOrTag      string    `bun:"branch_or_tag"`
	BranchOrTagShown string    `bun:"branch_or_tag_shown"`
	Variant          string    `bun:"variant"`
	VariantShown     string    `bun:"variant_shown"`
	Series           string    `bun:"series"`
	Kind             kind.Kind `bun:"kind"`
}
