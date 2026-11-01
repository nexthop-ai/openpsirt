// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// StatedPurls is, for each component given with an open node in the build, the
// package identifier the build stated for it: its open image version's, else
// its open node's, null where the build states none. A component with no open
// node is absent, so the map also says what still ships.
//
// The component row is shared by every product shipping the package, and the
// build's node holds what this build stated. A container image is stored with
// no version, and its open image version holds the identifier this build
// stamped it with: a product named with no version is one a reader cannot
// match. A build holds one open node per component and a node one open image
// version, so the least is the one.
//
// Read as three sets keyed by constant lists: the open nodes, the nodes' own
// identifiers, and their open image versions. A statement reading one table by
// constants, or joining another by its primary key, has no plan that reads a
// table once per row, whatever the statistics say.
func StatedPurls(ctx context.Context, db bun.IDB, buildID int64,
	components []int64) (map[int64]sql.NullString, error) {

	if len(components) == 0 {
		return nil, nil
	}
	byComponent, args := database.InAnyOf(`"n"."component_id"`, components)
	var nodes []int64
	if err := db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."id"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(byComponent, args...).
		Scan(ctx, &nodes); err != nil {
		return nil, fmt.Errorf("read the components the build still ships: %w", err)
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	type stated struct {
		ComponentID int64          `bun:"component_id"`
		Purl        sql.NullString `bun:"purl"`
	}
	var placed, imaged []stated
	byNode, args := database.InAnyOf(`"n"."id"`, nodes)
	if err := db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."component_id" AS "component_id"`).
		ColumnExpr(`MIN("n"."purl") AS "purl"`).
		Where(byNode, args...).
		GroupExpr(`"n"."component_id"`).
		Scan(ctx, &placed); err != nil {
		return nil, fmt.Errorf("read the package identifiers the build states: %w", err)
	}
	byVersion, args := database.InAnyOf(`"sv"."node_id"`, nodes)
	if err := db.NewSelect().
		TableExpr(`"image_version" AS "sv"`).
		Join(`JOIN "graph_node" AS "n" ON "n"."id" = "sv"."node_id"`).
		ColumnExpr(`"n"."component_id" AS "component_id"`).
		ColumnExpr(`MIN("sv"."purl") AS "purl"`).
		Where(byVersion, args...).
		Where(`"sv"."closed_scan_id" IS NULL`).
		GroupExpr(`"n"."component_id"`).
		Scan(ctx, &imaged); err != nil {
		return nil, fmt.Errorf("read the package identifiers the build's images state: %w", err)
	}
	purls := make(map[int64]sql.NullString, len(placed))
	for _, row := range placed {
		purls[row.ComponentID] = row.Purl
	}
	for _, row := range imaged {
		if row.Purl.Valid {
			purls[row.ComponentID] = row.Purl
		}
	}
	return purls, nil
}

// Grouped is what one statement about a build is about: an issue, and a
// component by its name and the package identifier the build stated, or the
// component's own where the build stated none.
type Grouped struct {
	VulnerabilityID int64  `bun:"vulnerability_id"`
	Identifier      string `bun:"identifier"`
	Component       string `bun:"component"`
	Purl            string `bun:"purl"`
}

// CoveredGroup is a group of a build's open occurrences wholly covered by
// approved, live decisions agreeing on one outcome.
type CoveredGroup struct {
	Grouped
	Covering
}

// AffectedGroup is a group of a build's open occurrences wholly under
// decisions in force that the issue applies.
type AffectedGroup struct {
	Grouped
	Affected
}

// CoveredInBuild is what a VEX document of one build states from agreed
// decisions, at the visibilities given: every group of the build's open
// findings whose every open occurrence is covered by approved, live decisions
// agreeing on one outcome, as WhollyCovered asks it, and what is stated
// occurrence by occurrence where a group's occurrences disagree
// (CoveredAtOccurrences). Each is up to one past most, so that reaching the
// ceiling is distinguishable from landing on it.
//
// A group is an issue and a component by its name and stated package
// identifier (StatedPurls), so a group merges components of one name and
// stated identifier. An occurrence with no covering decision makes its group
// fail.
//
// Only issues a covering decision exists for in the product are read; a wholly
// covered group has at least one. The build's undecided occurrences are most
// of it, and an engine estimating the finding table at a few rows otherwise
// works out the decisions of every one of them: 1.2 s on MySQL for one build
// of 84,000 findings. The findings and decisions of those issues are read as
// sets (readDecided), once for both.
func CoveredInBuild(ctx context.Context, db bun.IDB, productID, buildID int64,
	visible []access.Visibility, most int) ([]CoveredGroup, []OccurrenceCovered, error) {

	read := decidedRead{state: `"de"."state" = 'approved'`, outcomes: coveringOutcomes(ForStatements)}
	sets, err := decidedOf(ctx, db, productID, buildID, visible, read)
	if err != nil || sets == nil {
		return nil, nil, err
	}
	var rows []CoveredGroup
	for g, t := range sets.groups() {
		if t.agreed() {
			rows = append(rows, CoveredGroup{Grouped: g, Covering: Covering{Outcome: t.least, DecidedBy: t.first}})
		}
	}
	placed, err := sets.coveredAtOccurrences(ctx, db, buildID, most)
	if err != nil {
		return nil, nil, err
	}
	return firstGroups(rows, func(r CoveredGroup) Grouped { return r.Grouped }, most), placed, nil
}

// AffectedInBuild is every group of one build's open findings, at the
// visibilities given, whose every open occurrence stands under a decision in
// force that the issue applies, up to one past most. It reads as
// CoveredInBuild does.
func AffectedInBuild(ctx context.Context, db bun.IDB, productID, buildID int64,
	visible []access.Visibility, most int) ([]AffectedGroup, error) {

	standing, args := InForce()
	read := decidedRead{state: standing, stateArgs: args, outcomes: affectingOutcomes()}
	sets, err := decidedOf(ctx, db, productID, buildID, visible, read)
	if err != nil || sets == nil {
		return nil, err
	}
	var rows []AffectedGroup
	for g, t := range sets.groups() {
		if t.decided == t.joined {
			rows = append(rows, AffectedGroup{Grouped: g,
				Affected: Affected{Least: t.least, Greatest: t.greatest, DecidedBy: t.first}})
		}
	}
	return firstGroups(rows, func(r AffectedGroup) Grouped { return r.Grouped }, most), nil
}

// decidedOf is the open findings of the issues a decision the read counts
// exists for in the product, with their decisions, or nil where there is none.
func decidedOf(ctx context.Context, db bun.IDB, productID, buildID int64, visible []access.Visibility,
	read decidedRead) (*decidedSets, error) {

	issues, err := issuesDecided(ctx, db, productID, buildID, visible, read.state, read.stateArgs, read.outcomes)
	if err != nil || len(issues) == 0 {
		return nil, err
	}
	return readDecided(ctx, db, productID, buildID, visible, issues, read)
}

// issuesDecided is every issue a live decision occurrence of the product, at
// the visibilities given, in the state given and with an outcome `cl` the
// condition given accepts, is filed under, that the build holds open at those
// visibilities.
//
// The build bounds the list. A product decides issues across every build it
// ever had, and a long-lived one decides far more than one build holds: with
// 100,000 decided issues outside the build, the findings are otherwise read
// against 100,300 issues where the build holds 300.
//
// The build is asked by issue alone, as a set the statement reads once, and
// the occurrence is matched by readDecided. Asked of each decision occurrence
// at its occurrence, MySQL on the statistics a bulk load leaves reads every
// finding at the occurrence before it knows the issue, once per decision
// occurrence: past 30 s for a long-lived product, against 0.21 s.
func issuesDecided(ctx context.Context, db bun.IDB, productID, buildID int64, visible []access.Visibility,
	state string, stateArgs []any, outcomes string) ([]int64, error) {

	kinds, kindArgs := kind.VEX.Where(`"bf"."kind"`)
	held := append([]any{buildID, bun.List(visible)}, kindArgs...)
	var issues []int64
	if err := db.NewSelect().
		Distinct().
		TableExpr(`"decision_occurrence" AS "de"`).
		Join(DecisionOccurrenceIssue).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		ColumnExpr(`"dv"."issue_id"`).
		Where(`"de"."product_id" = ?`, productID).
		Where(state, stateArgs...).
		Where(`"de"."live_key" IS NOT NULL`).
		Where(`"de"."visibility" IN (?)`, bun.List(visible)).
		Where(outcomes).
		Where(`"dv"."issue_id" IN (SELECT "bf"."vulnerability_id" FROM "finding" AS "bf"
			WHERE "bf"."build_id" = ? AND "bf"."closed_at" IS NULL AND "bf"."visibility" IN (?)
			AND `+kinds+`)`, held...).
		Scan(ctx, &issues); err != nil {
		return nil, fmt.Errorf("read the issues decided in this product: %w", err)
	}
	return issues, nil
}
