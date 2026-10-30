// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
	"github.com/nexthop-ai/openpsirt/internal/weakness"
)

// Release is the code findings one tagged release holds now, one frozen point
// on a line of releases.
type Release struct {
	// BranchOrTag is the name an address gives the tag, and Shown the one a
	// person reads.
	BranchOrTag, Shown string
	// Cut is when the release went out, where somebody said, and when it was
	// declared otherwise. It orders the releases; the axis is the sequence.
	Cut time.Time
	// NotFixed is the code findings on its builds nobody closed as fixed,
	// whatever was decided about them, and ByTier the split, every tier
	// named.
	NotFixed int
	ByTier   map[string]int
	// Open, Dismissed and NoLongerDetected are those of them in that state
	// on a build of the release: open, answered as noise by a decision or a
	// suppression rule, and unseen by a comparable run. A code finding on two
	// builds in two states counts in both, as the queue counts it.
	Open, Dismissed, NoLongerDetected int
}

// ByRelease is the code findings each tagged release of the product holds
// now, oldest release first, the newest limit of them (REQ-54).
//
// A tag is one frozen point, so its code findings are answered today, as the
// queue answers them on its builds, and never drawn as a line between
// releases. A release is a point once a run of a series in the scope was
// applied to one of its builds, so a release with nothing open is a point at
// zero and a release never analyzed is absent. Counted by occurrence, once
// however many of the release's builds hold it.
//
// Refused to anybody who does not read security testing material in the
// product, before any name in the scope is resolved.
func ByRelease(ctx context.Context, db bun.IDB, subject access.Subject, scope Scope,
	limit int) ([]Release, error) {

	if err := MayCount(subject, scope.ProductID, "count the code findings of each release"); err != nil {
		return nil, err
	}
	visible, err := finding.CodeFindingVisible(subject, scope.ProductID)
	if err != nil {
		return nil, err
	}
	// A release line is the tags; a branch named would narrow it to nothing.
	scope.BranchOrTagID = nil
	if scope, err = scope.resolved(ctx, db); err != nil {
		return nil, err
	}

	named, namedArgs := kind.SecurityTestingStatistics.Where(`"se"."kind"`)
	analyzed := db.NewSelect().TableExpr(`"build" AS "t"`).
		Join(`JOIN "series_run" AS "sr" ON "sr"."build_id" = "t"."id"`).
		Join(`JOIN "series" AS "se" ON "se"."id" = "sr"."series_id"`).
		ColumnExpr(`1`).
		Where(`"t"."branch_or_tag_id" = "s"."id"`).
		Where(`"sr"."status" = ?`, series.Applied).
		Where(named, namedArgs...)
	if scope.VariantID != nil {
		analyzed = analyzed.Where(`"t"."variant_id" = ?`, *scope.VariantID)
	}
	if scope.Method != "" {
		analyzed = analyzed.Where(`"se"."kind" = ?`, methodKinds[scope.Method])
	}
	if scope.Series != "" {
		analyzed = analyzed.Where(`"se"."name_folded" = ?`, typedname.Matching(scope.Series))
	}
	var tags []struct {
		ID    int64     `bun:"id"`
		Name  string    `bun:"name"`
		Shown string    `bun:"shown"`
		Cut   time.Time `bun:"cut"`
	}
	// The day it went out, where somebody said, and the day it was declared
	// otherwise, as the release line of vulnerabilities orders them.
	if err := db.NewSelect().TableExpr(`"branch_or_tag" AS "s"`).
		ColumnExpr(`"s"."id", "s"."name", `+catalog.ShownExpr("s")+` AS "shown"`).
		ColumnExpr(`COALESCE("s"."released_on", "s"."created_at") AS "cut"`).
		Where(`"s"."product_id" = ?`, scope.ProductID).
		Where(`"s"."kind" = ?`, catalog.Tag).
		Where(`EXISTS (?)`, analyzed).
		OrderExpr(`"cut", "s"."name"`).
		Scan(ctx, &tags); err != nil {
		return nil, fmt.Errorf("read the analyzed releases of product %d: %w", scope.ProductID, err)
	}
	// The most recent, where there are more than a chart carries: the
	// releases somebody compares are the recent ones.
	if limit = database.APlot.Of(limit); len(tags) > limit {
		tags = tags[len(tags)-limit:]
	}
	out := make([]Release, len(tags))
	index := map[int64]int{}
	ids := make([]int64, len(tags))
	for i, tag := range tags {
		out[i] = Release{BranchOrTag: tag.Name, Shown: tag.Shown, Cut: tag.Cut, ByTier: map[string]int{}}
		for _, tier := range weakness.Tiers() {
			out[i].ByTier[tier.Name()] = 0
		}
		index[tag.ID] = i
		ids[i] = tag.ID
	}
	if len(tags) == 0 {
		return out, nil
	}

	// The queue's own rows, in each state, so a release's counts are the
	// lists the queue gives for its builds.
	var rows []struct {
		BranchOrTagID int64  `bun:"branch_or_tag_id"`
		Occurrence    string `bun:"occurrence_identity"`
		Stands        State  `bun:"stands"`
		Tier          int    `bun:"tier"`
	}
	if err := db.NewSelect().TableExpr(`(?) AS "l"`, openCodeFindingFindings(db, subject, scope, visible)).
		ColumnExpr(`"l"."branch_or_tag_id", "l"."occurrence_identity", "l"."stands", MAX("l"."tier") AS "tier"`).
		Where(`"l"."branch_or_tag_id" IN (?)`, bun.List(ids)).
		GroupExpr(`"l"."branch_or_tag_id", "l"."occurrence_identity", "l"."stands"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("count the code findings of each release of product %d: %w", scope.ProductID, err)
	}
	type held struct {
		tier   int
		states map[State]bool
	}
	per := make([]map[string]*held, len(out))
	for i := range per {
		per[i] = map[string]*held{}
	}
	for _, row := range rows {
		i := index[row.BranchOrTagID]
		one := per[i][row.Occurrence]
		if one == nil {
			one = &held{states: map[State]bool{}}
			per[i][row.Occurrence] = one
		}
		one.tier = max(one.tier, row.Tier)
		one.states[row.Stands] = true
	}
	for i, occurrences := range per {
		for _, one := range occurrences {
			out[i].NotFixed++
			out[i].ByTier[weakness.Tier(one.tier).Name()]++
			if one.states[Open] {
				out[i].Open++
			}
			if one.states[Dismissed] || one.states[NotSecurity] {
				out[i].Dismissed++
			}
			if one.states[NoLongerDetected] {
				out[i].NoLongerDetected++
			}
		}
	}
	return out, nil
}
