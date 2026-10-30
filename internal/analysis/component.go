// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// BuildCount is how many open code findings one build places on a source
// package at one version.
type BuildCount struct {
	BranchOrTag string `bun:"branch_or_tag"`
	Variant     string `bun:"variant"`
	// Version is the version the source package was built at, as the
	// component screen names it.
	Version string `bun:"source_version"`
	Open    int    `bun:"open"`
}

// ComponentCounts is how many code findings a product places on one source
// package: per analyzer series and state over every build, and the open ones
// per build and source version.
type ComponentCounts struct {
	Series []SeriesCount
	Builds []BuildCount
}

// MayCount refuses a count of code findings to anybody who does not read
// security testing material in the product: every count of code findings,
// figures, tree, trend and chooser alike, asks it. A count is at security
// testing visibility however it is narrowed; a flaw's reader reads one code
// finding, not the figures.
func MayCount(subject access.Subject, productID int64, what string) error {
	if !subject.Sees(productID) || !subject.Reads(access.SecurityTesting, productID) {
		return access.Denied(fmt.Sprintf("%s of product %d", what, productID))
	}
	return nil
}

// CountsOfComponent is how many code findings a product places on the source
// package scope.Component names, read as the queue reads them for the same
// reader, so each count is the length of the list asking for that component,
// series and state. Every series of the product is listed, zero included.
//
// Unplaced on each series is the open code findings placed on the build
// itself: a build's root is a component, and what no repository of the build
// holds is placed there. Counted only where the name names a build's root,
// over every component that was ever that build's root, named as values.
func CountsOfComponent(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope) (*ComponentCounts, error) {
	if err := MayCount(subject, scope.ProductID, "count the code findings of a component"); err != nil {
		return nil, err
	}
	visible, err := finding.CodeFindingVisible(subject, scope.ProductID)
	if err != nil {
		return nil, err
	}
	if scope, err = scope.resolved(ctx, db); err != nil {
		return nil, err
	}
	series, err := countBySeries(ctx, db, subject, scope, visible)
	if err != nil {
		return nil, err
	}

	if scope.reached != nil && len(scope.reached.Roots) > 0 {
		var unplaced []struct {
			SeriesID     int64 `bun:"series_id"`
			CodeFindings int   `bun:"code_findings"`
		}
		if err := db.NewSelect().
			TableExpr(`(?) AS "l"`, codeFindingFindings(db, subject, scope, visible)).
			ColumnExpr(`"l"."series_id", COUNT(DISTINCT "l"."occurrence_identity") AS "code_findings"`).
			Where(`"l"."stands" = ?`, string(Open)).
			Where(`"l"."component_id" IN (?)`, bun.List(scope.reached.Roots)).
			GroupExpr(`"l"."series_id"`).
			Scan(ctx, &unplaced); err != nil {
			return nil, fmt.Errorf("count the unplaced code findings of product %d: %w", scope.ProductID, err)
		}
		for _, each := range unplaced {
			if one, ok := series.at[each.SeriesID]; ok {
				one.Unplaced = each.CodeFindings
			}
		}
	}

	out := &ComponentCounts{Series: series.out}
	if err := db.NewSelect().
		TableExpr(`(?) AS "l"`, codeFindingFindings(db, subject, scope, visible)).
		Join(`JOIN "component" AS "c" ON "c"."id" = "l"."component_id"`).
		Join(`JOIN "build" AS "t" ON "t"."id" = "l"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"`).
		ColumnExpr(`"s"."name" AS "branch_or_tag", "va"."name" AS "variant"`).
		ColumnExpr(finding.SourceVersion+` AS "source_version"`).
		ColumnExpr(`COUNT(DISTINCT "l"."occurrence_identity") AS "open"`).
		Where(`"l"."stands" = ?`, string(Open)).
		GroupExpr(`"s"."name", "va"."name", `+finding.SourceVersion).
		OrderExpr(`"s"."name", "va"."name", `+finding.SourceVersion).
		Scan(ctx, &out.Builds); err != nil {
		return nil, fmt.Errorf("count the open code findings of a component per build in product %d: %w", scope.ProductID, err)
	}
	return out, nil
}

// OpenOn is the open code findings one build places on each of these
// components, by occurrence, where the subject may read them; nil components
// is every component of the build. A component counts as well the code
// findings on every version of it a rescan replaced, which no node of the
// build holds. Refused to anybody who does not read security testing material
// in the product, as every count of code findings is.
func OpenOn(ctx context.Context, db bun.IDB, subject access.Subject, productID, buildID int64,
	components []int64) (map[int64][]string, error) {

	if err := MayCount(subject, productID, "count the code findings in the tree"); err != nil {
		return nil, err
	}
	out := map[int64][]string{}
	if components != nil && len(components) == 0 {
		return out, nil
	}
	visible, err := finding.CodeFindingVisible(subject, productID)
	if err != nil {
		return nil, err
	}
	read := func(on []int64) (map[int64][]string, error) {
		var rows []struct {
			ComponentID int64  `bun:"component_id"`
			Occurrence  string `bun:"occurrence_identity"`
		}
		scope := Scope{ProductID: productID, BuildID: &buildID, on: on}
		if err := db.NewSelect().
			TableExpr(`(?) AS "l"`, codeFindingFindings(db, subject, scope, visible)).
			ColumnExpr(`"l"."component_id", "l"."occurrence_identity"`).
			Where(`"l"."stands" = ?`, string(Open)).
			GroupExpr(`"l"."component_id", "l"."occurrence_identity"`).
			Scan(ctx, &rows); err != nil {
			return nil, fmt.Errorf("read the open code findings on components of build %d: %w", buildID, err)
		}
		got := map[int64][]string{}
		for _, row := range rows {
			got[row.ComponentID] = append(got[row.ComponentID], row.Occurrence)
		}
		return got, nil
	}
	if out, err = read(components); err != nil {
		return nil, err
	}
	replaced, err := replacedIn(ctx, db, buildID)
	if err != nil || len(replaced) == 0 {
		return out, err
	}
	asked := map[int64]bool{}
	for _, id := range components {
		asked[id] = true
	}
	var wanted []int64
	for id, live := range replaced {
		for _, l := range live {
			if components == nil || asked[l] {
				wanted = append(wanted, id)
				break
			}
		}
	}
	on := out
	if components != nil {
		if len(wanted) == 0 {
			return out, nil
		}
		if on, err = read(wanted); err != nil {
			return nil, err
		}
	}
	for _, id := range wanted {
		for _, l := range replaced[id] {
			if components == nil || asked[l] {
				out[l] = append(out[l], on[id]...)
			}
		}
	}
	return out, nil
}

// TrendPoint is the code findings at a moment: those not fixed, and those
// opened and fixed in the step it ends.
type TrendPoint struct {
	At       time.Time
	NotFixed int
	Opened   int
	Fixed    int
}

// TrendBeneath is the code findings one build places at a component or
// anywhere under it, step by step: how many were not fixed at the end of each
// step, and how many were opened and fixed in it. Plotted on when a run was
// applied, as the dependency trend is.
//
// A code finding is not fixed from when it opened until a person closes it as
// fixed: absence closes nothing, and a decision answers a code finding
// without closing it. Under the build's root it is every code finding of the
// build, as the queue beneath the root lists them.
// Refused to anybody who does not read security testing material in the
// product.
func TrendBeneath(ctx context.Context, db bun.IDB, subject access.Subject, productID, buildID, beneath int64,
	since time.Time, step time.Duration, steps int) ([]TrendPoint, error) {

	if err := MayCount(subject, productID, "trend the code findings of a component"); err != nil {
		return nil, err
	}
	visible, err := finding.CodeFindingVisible(subject, productID)
	if err != nil {
		return nil, err
	}
	whole, err := graph.IsRoot(ctx, db, buildID, beneath)
	if err != nil {
		return nil, err
	}
	until := since.Add(time.Duration(steps) * step)
	reach := finding.CodeFindingReach(subject, productID)
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	var rows []struct {
		Occurrence string     `bun:"occurrence_identity"`
		OpenedAt   time.Time  `bun:"opened_at"`
		ClosedAt   *time.Time `bun:"closed_at"`
	}
	q := db.NewSelect().TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."occurrence_identity", "f"."opened_at", "f"."closed_at"`).
		Where(`"f"."build_id" = ?`, buildID)
	if !whole {
		replaced, err := replacedIn(ctx, db, buildID)
		if err != nil {
			return nil, err
		}
		adopted, err := replacedWithin(ctx, db, buildID, beneath, replaced)
		if err != nil {
			return nil, err
		}
		cond, args := beneathOrAdopted(db, buildID, beneath, adopted)
		q = q.Where(cond, args...)
	}
	err = q.Where(kinds, kindArgs...).
		Where(`("f"."visibility" IN (?) OR `+reach.Included+`)`, append([]any{bun.List(visible)}, reach.IncludedArgs...)...).
		Where(`"f"."opened_at" <= ?`, until).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr(`"f"."closed_at" IS NULL`).WhereOr(`"f"."closed_at" > ?`, since)
		}).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read the code findings beneath a component of build %d over time: %w", buildID, err)
	}

	// Each step is the set of occurrences not fixed at its end, and the flows
	// are the difference between one set and the last, so the three numbers
	// agree. A code finding closes only as fixed.
	open := make([]map[string]bool, steps)
	for i := range open {
		open[i] = map[string]bool{}
	}
	for _, row := range rows {
		for i := 0; i < steps; i++ {
			to := since.Add(time.Duration(i+1) * step)
			if row.OpenedAt.After(to) || (row.ClosedAt != nil && !row.ClosedAt.After(to)) {
				continue
			}
			open[i][row.Occurrence] = true
		}
	}
	points := make([]TrendPoint, 0, steps)
	for i := 0; i < steps; i++ {
		point := TrendPoint{At: since.Add(time.Duration(i+1) * step), NotFixed: len(open[i])}
		if i > 0 {
			for occurrence := range open[i] {
				if !open[i-1][occurrence] {
					point.Opened++
				}
			}
			for occurrence := range open[i-1] {
				if !open[i][occurrence] {
					point.Fixed++
				}
			}
		}
		points = append(points, point)
	}
	return points, nil
}

// OpenOfMatches is the open code findings on each matched source package in
// its product's builds in scope, as the queue counts them for the same reader
// asked for the source by name. A match in a product where the subject does
// not read security testing material has no entry: a count of code findings
// is at that visibility.
//
// What each name reaches is read first, in the match's builds, and bound as
// values, so a name reaches only what those builds hold.
func OpenOfMatches(ctx context.Context, db bun.IDB, subject access.Subject,
	matches []finding.SourceMatch) (map[int]int, error) {

	out := map[int]int{}
	byProduct := map[int64][]int{}
	for i, m := range matches {
		byProduct[m.ProductID] = append(byProduct[m.ProductID], i)
	}
	for productID, at := range byProduct {
		if MayCount(subject, productID, "count the code findings of components") != nil {
			continue
		}
		visible, err := finding.CodeFindingVisible(subject, productID)
		if err != nil {
			return nil, err
		}
		builds := matches[at[0]].Builds
		names := make([]string, 0, len(at))
		for _, i := range at {
			names = append(names, matches[i].Folded)
		}
		reached, err := finding.ReachedByName(ctx, db, builds, names, "")
		if err != nil {
			return nil, err
		}
		open := map[string]int{}
		if folds := finding.FoldsOf(reached); len(folds) > 0 {
			scope := Scope{ProductID: productID, reached: &finding.Reached{Folds: folds}}
			keyed := db.NewSelect().
				TableExpr(`(?) AS "l"`, codeFindingFindings(db, subject, scope, visible)).
				Join(`JOIN "component" AS "lc" ON "lc"."id" = "l"."component_id"`).
				ColumnExpr(`"lc"."fold_key", "l"."occurrence_identity" AS "key"`).
				Where(`"l"."stands" = ?`, string(Open)).
				Where(`"l"."build_id" IN (?)`, bun.List(builds)).
				Distinct()
			if open, err = finding.OpenByName(ctx, keyed, reached); err != nil {
				return nil, fmt.Errorf("count the open code findings on components of product %d: %w", productID, err)
			}
		}
		for _, i := range at {
			out[i] = open[matches[i].Folded]
		}
	}
	return out, nil
}
