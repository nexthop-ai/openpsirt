// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// MostTrendSteps is the most steps a trend is worked out over: two years of
// weeks.
const MostTrendSteps = 104

// TrendPoint is the code findings at a moment: those not fixed, split by the
// tier of their rule's weaknesses, by series and by testing method, and those
// opened and fixed in the step it ends.
type TrendPoint struct {
	At       time.Time
	NotFixed int
	Opened   int
	Fixed    int
	// ByTier, BySeries and ByMethod split NotFixed. Every tier and method is
	// named, zero included; a series is named once a code finding of it is
	// counted anywhere in the trend.
	ByTier   map[string]int
	BySeries map[string]int
	ByMethod map[string]int
}

// Change is what a marker on a trend says moved under a series.
type Change string

const (
	// ToolChanged is a run by another tool than the series' run before it
	// on the build.
	ToolChanged Change = "tool"
	// VersionChanged is a run by another version of the same tool.
	VersionChanged Change = "tool-version"
	// RulesChanged is a run with another rule set.
	RulesChanged Change = "rules"
	// NotComparable is a run whose absences are no evidence for a reason
	// other than a change of tool or rules: it failed, did not finish, or
	// covered too little.
	NotComparable Change = "not-comparable"
)

// Changes is every change a marker says, in the order a marker is listed.
func Changes() []Change { return []Change{NotComparable, RulesChanged, ToolChanged, VersionChanged} }

// Marker is runs of one series applied on one day that changed what the
// trend is comparing: each move from a run before to the run applied, or a
// run whose absences are no evidence.
type Marker struct {
	// At is the day the runs were applied, at midnight UTC.
	At     time.Time
	Series string
	Change Change
	// Reason is why the runs were not comparable, on NotComparable alone.
	Reason series.Reason
	// From and To are the tool, the version or the count of rules before
	// and after, empty where a run states none. Empty on NotComparable.
	From, To string
	// Builds is how many builds the change was made on that day.
	Builds int
}

// Trended is code findings over time.
type Trended struct {
	Points  []TrendPoint
	Markers []Marker
	// NoLongerDetected is how many code findings in the scope a comparable
	// run did not see, now: the queue's count of that state. A return after
	// an absence clears it, so it has no history to draw week by week.
	NoLongerDetected int
}

// Trend is the code findings in a scope step by step: how many were not fixed
// at the end of each step, split by tier, series and method, how many were
// opened and fixed in it, the runs that changed the tool, its version or its
// rules or were not comparable, and how many are no longer detected now.
// Plotted on when a run was applied, as the dependency trend is. A step holds
// its start and not its end, so a moment is in one step alone.
//
// A code finding is not fixed from when it opened until a person closes it as
// fixed: absence closes nothing, and a decision answers a code finding
// without closing it. It is counted by occurrence, once however many builds
// in the scope hold it, and not fixed while any of them holds it unfixed.
// Under a build's root it is every code finding of the build, as the queue
// beneath the root lists them.
//
// The tier is the rule's as it is rated now. Refused to anybody who does not
// read security testing material in the product, before any name in the scope
// is resolved.
func Trend(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	since time.Time, step time.Duration, steps int) (*Trended, error) {

	if err := MayCount(subject, scope.ProductID, "trend the code findings"); err != nil {
		return nil, err
	}
	if steps < 1 || steps > MostTrendSteps || step <= 0 {
		return nil, fmt.Errorf("trend code findings over %d steps of %s: out of range", steps, step)
	}
	visible, err := finding.CodeFindingVisible(subject, scope.ProductID)
	if err != nil {
		return nil, err
	}
	if scope, err = scope.resolved(ctx, db); err != nil {
		return nil, err
	}
	until := since.Add(time.Duration(steps) * step)
	out := &Trended{}
	if out.Points, err = trendPoints(ctx, db, subject, scope, visible, since, step, steps); err != nil {
		return nil, err
	}
	if out.Markers, err = trendMarkers(ctx, db, scope, since, until); err != nil {
		return nil, err
	}
	if out.NoLongerDetected, err = noLongerDetected(ctx, db, subject, scope, visible); err != nil {
		return nil, err
	}
	return out, nil
}

// trendPoints is the steps of a trend.
//
// Each step is the set of occurrences not fixed at its end, and the flows are
// the difference between one set and the last, so the three numbers agree. A
// code finding closes only as fixed. The set is a bit per step on each
// occurrence, read in one statement and counted here, because a statement per
// step is a hundred round trips for one answer.
func trendPoints(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	visible []access.Visibility, since time.Time, step time.Duration, steps int) ([]TrendPoint, error) {

	until := since.Add(time.Duration(steps) * step)
	var rows []struct {
		Occurrence string     `bun:"occurrence_identity"`
		Kind       kind.Kind  `bun:"kind"`
		SeriesID   int64      `bun:"series_id"`
		Tier       int        `bun:"tier"`
		OpenedAt   time.Time  `bun:"opened_at"`
		ClosedAt   *time.Time `bun:"closed_at"`
	}
	q := statisticsFindings(db, subject, scope, visible).
		ColumnExpr(`"f"."occurrence_identity", "f"."kind", "si"."series_id"`).
		ColumnExpr(`COALESCE("rr"."weakness_tier", 0) AS "tier"`).
		ColumnExpr(`"f"."opened_at", "f"."closed_at"`).
		Where(`"f"."opened_at" < ?`, until).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr(`"f"."closed_at" IS NULL`).WhereOr(`"f"."closed_at" >= ?`, since)
		})
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the code findings of product %d over time: %w", scope.ProductID, err)
	}
	names, err := seriesNames(ctx, db, scope.ProductID)
	if err != nil {
		return nil, err
	}

	type occurrence struct {
		series, method, tier string
		open                 [2]uint64
	}
	at := map[string]*occurrence{}
	for _, row := range rows {
		one := at[row.Occurrence]
		if one == nil {
			one = &occurrence{
				series: names[row.SeriesID], method: string(methodOf(row.Kind)),
				tier: weakness.Tier(row.Tier).Name(),
			}
			at[row.Occurrence] = one
		}
		for i := 0; i < steps; i++ {
			to := since.Add(time.Duration(i+1) * step)
			if !row.OpenedAt.Before(to) || (row.ClosedAt != nil && row.ClosedAt.Before(to)) {
				continue
			}
			one.open[i/64] |= 1 << (i % 64)
		}
	}
	isOpen := func(o *occurrence, i int) bool { return o.open[i/64]&(1<<(i%64)) != 0 }

	counted := map[string]bool{}
	for _, o := range at {
		if o.open != [2]uint64{} {
			counted[o.series] = true
		}
	}
	points := make([]TrendPoint, steps)
	for i := range points {
		p := TrendPoint{
			At:     since.Add(time.Duration(i+1) * step),
			ByTier: map[string]int{}, BySeries: map[string]int{}, ByMethod: map[string]int{},
		}
		for _, tier := range weakness.Tiers() {
			p.ByTier[tier.Name()] = 0
		}
		for method := range methodKinds {
			p.ByMethod[string(method)] = 0
		}
		for name := range counted {
			p.BySeries[name] = 0
		}
		for _, o := range at {
			now := isOpen(o, i)
			if now {
				p.NotFixed++
				p.ByTier[o.tier]++
				p.BySeries[o.series]++
				p.ByMethod[o.method]++
			}
			if i == 0 {
				continue
			}
			before := isOpen(o, i-1)
			if now && !before {
				p.Opened++
			}
			if before && !now {
				p.Fixed++
			}
		}
		points[i] = p
	}
	return points, nil
}

// statisticsFindings is every finding of the Security testing statistics
// consumer's kinds in the scope that the subject may read, one row per
// finding, with its sighting under "si", its build under "t", its branch or
// tag under "s" and its rule's rating under "rr", and no columns: each figure
// names its own. A finding closed and a finding opened anew at its occurrence
// are two rows.
//
// The product's own visibilities, and a code finding included in its flaw's
// case (REQ-43). Narrowed as the queue narrows, so a figure narrowed alike
// counts the list it opens.
func statisticsFindings(db bun.IDB, subject access.Subject, scope Scope, visible []access.Visibility) *bun.SelectQuery {
	kinds, kindArgs := kind.SecurityTestingStatistics.Where(`"f"."kind"`)
	reach := finding.CodeFindingReach(subject, scope.ProductID)
	q := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
		Join(`JOIN "build" AS "t" ON "t"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
		Join(`LEFT JOIN "rule_rating" AS "rr" ON "rr"."vulnerability_id" = "f"."vulnerability_id"`).
		Where(kinds, kindArgs...).
		Where(`("f"."visibility" IN (?) OR `+reach.Included+`)`, append([]any{bun.List(visible)}, reach.IncludedArgs...)...)
	return scope.narrow(db, scope.inScope(q), kind.SecurityTestingStatistics)
}

// methodOf is the testing method that records findings of a kind.
func methodOf(k kind.Kind) Method {
	for method, recorded := range methodKinds {
		if recorded == k {
			return method
		}
	}
	return ""
}

// seriesNames is the name of every series of a product a security testing
// figure counts, by identifier.
func seriesNames(ctx context.Context, db bun.IDB, productID int64) (map[int64]string, error) {
	kinds, kindArgs := kind.SecurityTestingStatistics.Where(`"se"."kind"`)
	var named []struct {
		ID   int64  `bun:"id"`
		Name string `bun:"name"`
	}
	if err := db.NewSelect().TableExpr(`"series" AS "se"`).
		ColumnExpr(`"se"."id", "se"."name"`).
		Where(`"se"."product_id" = ?`, productID).
		Where(kinds, kindArgs...).
		Scan(ctx, &named); err != nil {
		return nil, fmt.Errorf("read the analyzer series of product %d: %w", productID, err)
	}
	out := make(map[int64]string, len(named))
	for _, each := range named {
		out[each.ID] = each.Name
	}
	return out, nil
}

// trendMarkers is the runs applied in the range that changed what the trend
// compares, one marker per day, series and change, with how many builds it was
// made on.
//
// A run by another tool, version or rule set than the series' run before it
// on the build is never comparable, so the runs read are the ones that are
// not, each beside the run applied before it on its build. A run's own reason
// names only the first that holds: one that failed and also moved to a new
// version is marked for both.
func trendMarkers(ctx context.Context, db bun.IDB, scope Scope, since, until time.Time) ([]Marker, error) {
	named, namedArgs := kind.SecurityTestingStatistics.Where(`"se"."kind"`)
	var runs []struct {
		Series      string        `bun:"series"`
		BuildID     int64         `bun:"build_id"`
		AppliedAt   time.Time     `bun:"applied_at"`
		Reason      series.Reason `bun:"not_comparable"`
		Tool        *string       `bun:"tool_name"`
		Version     *string       `bun:"tool_version"`
		Rules       *string       `bun:"rules_digest"`
		RulesCount  *int          `bun:"rules_count"`
		Before      *int64        `bun:"before_id"`
		WasTool     *string       `bun:"was_tool_name"`
		WasVersion  *string       `bun:"was_tool_version"`
		WasRules    *string       `bun:"was_rules_digest"`
		WasRulesHad *int          `bun:"was_rules_count"`
	}
	applied := string(series.Applied)
	q := db.NewSelect().TableExpr(`"series_run" AS "sr"`).
		Join(`JOIN "series" AS "se" ON "se"."id" = "sr"."series_id"`).
		Join(`JOIN "build" AS "t" ON "t"."id" = "sr"."build_id"`).
		// The run applied before it on its build: the newest built before
		// it, which is the run it was compared with when it was applied.
		Join(`LEFT JOIN "series_run" AS "pr" ON "pr"."series_id" = "sr"."series_id"
			AND "pr"."build_id" = "sr"."build_id" AND "pr"."status" = ?
			AND "pr"."built_at" = (SELECT MAX("pb"."built_at") FROM "series_run" AS "pb"
				WHERE "pb"."series_id" = "sr"."series_id" AND "pb"."build_id" = "sr"."build_id"
				  AND "pb"."status" = ? AND "pb"."built_at" < "sr"."built_at")`, applied, applied).
		ColumnExpr(`"se"."name" AS "series", "sr"."build_id", "sr"."applied_at", "sr"."not_comparable"`).
		ColumnExpr(`"sr"."tool_name", "sr"."tool_version", "sr"."rules_digest", "sr"."rules_count"`).
		ColumnExpr(`"pr"."id" AS "before_id", "pr"."tool_name" AS "was_tool_name"`).
		ColumnExpr(`"pr"."tool_version" AS "was_tool_version", "pr"."rules_digest" AS "was_rules_digest"`).
		ColumnExpr(`"pr"."rules_count" AS "was_rules_count"`).
		Where(`"se"."product_id" = ?`, scope.ProductID).
		Where(named, namedArgs...).
		Where(`"sr"."status" = ?`, applied).
		Where(`"sr"."comparable" = FALSE`).
		Where(`"sr"."applied_at" >= ?`, since).
		Where(`"sr"."applied_at" < ?`, until)
	if scope.BranchOrTagID != nil {
		q = q.Where(`"t"."branch_or_tag_id" = ?`, *scope.BranchOrTagID)
	}
	// Beneath takes a branch and a variant naming its build, and a branch and
	// a variant have one build, so these two narrow the markers to it.
	if scope.VariantID != nil {
		q = q.Where(`"t"."variant_id" = ?`, *scope.VariantID)
	}
	if scope.Method != "" {
		q = q.Where(`"se"."kind" = ?`, methodKinds[scope.Method])
	}
	if scope.Series != "" {
		q = q.Where(`"se"."name_folded" = ?`, typedname.Matching(scope.Series))
	}
	if err := q.Scan(ctx, &runs); err != nil {
		return nil, fmt.Errorf("read the runs of product %d that changed what they compare: %w", scope.ProductID, err)
	}

	type key struct {
		at       time.Time
		series   string
		change   Change
		reason   series.Reason
		from, to string
	}
	// A series re-run on one build in a day is one change there.
	counted := map[key]map[int64]bool{}
	for _, run := range runs {
		day := run.AppliedAt.UTC().Truncate(24 * time.Hour)
		mark := func(change Change, reason series.Reason, from, to string) {
			k := key{at: day, series: run.Series, change: change, reason: reason, from: from, to: to}
			if counted[k] == nil {
				counted[k] = map[int64]bool{}
			}
			counted[k][run.BuildID] = true
		}
		if run.Before != nil {
			switch {
			case text(run.Tool) != text(run.WasTool):
				mark(ToolChanged, "", text(run.WasTool), text(run.Tool))
			case text(run.Version) != text(run.WasVersion):
				mark(VersionChanged, "", text(run.WasVersion), text(run.Version))
			}
			if text(run.Rules) != text(run.WasRules) {
				mark(RulesChanged, "", count(run.WasRulesHad), count(run.RulesCount))
			}
		}
		if run.Reason != series.ToolChanged && run.Reason != series.RulesChanged {
			mark(NotComparable, run.Reason, "", "")
		}
	}
	out := make([]Marker, 0, len(counted))
	for k, builds := range counted {
		out = append(out, Marker{
			At: k.at, Series: k.series, Change: k.change, Reason: k.reason, From: k.from, To: k.to,
			Builds: len(builds),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.At.Equal(b.At) {
			return a.At.Before(b.At)
		}
		if a.Series != b.Series {
			return a.Series < b.Series
		}
		if a.Change != b.Change {
			return a.Change < b.Change
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return out, nil
}

// text is a column a run may leave unstated, as words.
func text(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// count is a count a run may leave unstated, as words.
func count(n *int) string {
	if n == nil {
		return ""
	}
	return strconv.Itoa(*n)
}
