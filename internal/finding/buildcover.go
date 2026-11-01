// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// StatedPurl is the package identifier a build stated for a component of a
// finding `f`, given the column naming the component: its open image version's,
// else its open node's. Null where the build holds no open node for it, or the
// node states none.
//
// The component row is shared by every product shipping the package, and the
// build's node holds what this build stated. A container image is stored with
// no version, and its open image version holds the identifier this build
// stamped it with: a product named with no version is one a reader cannot
// match.
//
// A value asked of each row with its keys bound, never a join. Joined, an
// engine estimating the finding table at a few rows reads the build's whole
// graph once per finding: past a minute a statement on PostgreSQL for one
// build of 16,000 components. A build holds one open node per component and a
// node one open image version, so the least is the one.
//
// The open image version is asked of each open node with its keys bound,
// through the index on the node and its closing scan: one probe however many
// times the image was rebuilt. Picked out in an aggregate over every version of
// the node, each row read the image's whole history: 4.9 s against 0.21 s for
// the document on MariaDB, analyzed, with 1,000 rebuilds behind each image.
func StatedPurl(component string) string {
	switch component {
	case `"f"."component_id"`, `"f"."consumer_id"`:
	default:
		panic("finding.StatedPurl: " + component + " is not a component of a finding the statement names")
	}
	return `(SELECT COALESCE(MIN((SELECT MIN("sv"."purl") FROM "image_version" AS "sv"
			WHERE "sv"."node_id" = "sn"."id" AND "sv"."closed_scan_id" IS NULL)), MIN("sn"."purl"))
		FROM "graph_node" AS "sn"
		WHERE "sn"."build_id" = "f"."build_id" AND "sn"."component_id" = ` + component + `
			AND "sn"."closed_scan_id" IS NULL)`
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

// CoveredInBuild is every group of one build's open findings, at the
// visibilities given, whose every open occurrence is covered for one reader by
// approved, live decisions agreeing on one outcome, as WhollyCovered asks it:
// up to one past most, so that reaching the ceiling is distinguishable from
// landing on it.
//
// Read in two levels: each issue at each component first, then the groups a
// statement is about. The stated package identifier is asked once per
// component (StatedPurl), and a group merges components of one name and stated
// identifier. A component of a group with no covering decision makes the group
// fail, so the outer level sums what each component counted.
//
// Only issues a covering decision exists for in the product are read, named in
// the statement; a wholly covered group has at least one. The build's
// undecided occurrences are most of it, and an engine estimating the finding
// table at a few rows otherwise works out the decisions of every one of them:
// 1.2 s on MySQL for one build of 84,000 findings.
func CoveredInBuild(ctx context.Context, db bun.IDB, productID, buildID int64,
	visible []access.Visibility, reader Reader, most int) ([]CoveredGroup, error) {

	issues, err := issuesDecided(ctx, db, productID, buildID, visible, `"de"."state" = 'approved'`, nil,
		coveringOutcomes(reader))
	if err != nil || len(issues) == 0 {
		return nil, err
	}
	pairs := covered(issuesAtComponents(db, buildID, visible, issues), productID, visible, reader).
		ColumnExpr(`MAX("cl"."outcome") AS "greatest"`).
		ColumnExpr(`COUNT(*) AS "joined"`).
		ColumnExpr(`COUNT("cl"."id") AS "decided"`)
	var rows []CoveredGroup
	if err := statementGroups(db, pairs, most).
		ColumnExpr(`MIN("p"."outcome") AS "outcome"`).
		ColumnExpr(`MIN("p"."decided_by") AS "decided_by"`).
		Having(`MIN("p"."outcome") = MAX("p"."greatest")`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what stands about this build: %w", err)
	}
	return rows, nil
}

// AffectedInBuild is every group of one build's open findings, at the
// visibilities given, whose every open occurrence stands under a decision in
// force that the issue applies, up to one past most. It reads as
// CoveredInBuild does.
func AffectedInBuild(ctx context.Context, db bun.IDB, productID, buildID int64,
	visible []access.Visibility, most int) ([]AffectedGroup, error) {

	standing, args := InForce()
	issues, err := issuesDecided(ctx, db, productID, buildID, visible, standing, args, affectingOutcomes())
	if err != nil || len(issues) == 0 {
		return nil, err
	}
	pairs := affecting(issuesAtComponents(db, buildID, visible, issues), productID, visible).
		ColumnExpr(`COUNT(*) AS "joined"`).
		ColumnExpr(`COUNT("cl"."id") AS "decided"`)
	var rows []AffectedGroup
	if err := statementGroups(db, pairs, most).
		ColumnExpr(`MIN("p"."least") AS "least"`).
		ColumnExpr(`MAX("p"."greatest") AS "greatest"`).
		ColumnExpr(`MIN("p"."decided_by") AS "decided_by"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what applies in this build: %w", err)
	}
	return rows, nil
}

// issuesDecided is every issue a live decision occurrence of the product, at
// the visibilities given, in the state given and with an outcome `cl` the
// condition given accepts, is filed under, and the build holds open at those
// visibilities.
//
// The build bounds the list. A product decides issues across every build it
// ever had, and a long-lived one decides far more than one build holds: with
// 100,000 decided issues outside the build, the findings are otherwise read
// against 100,300 issues where the build holds 300. The bound costs one build
// 54 ms a statement on PostgreSQL against 2 ms.
func issuesDecided(ctx context.Context, db bun.IDB, productID, buildID int64, visible []access.Visibility,
	state string, stateArgs []any, outcomes string) ([]int64, error) {

	kinds, kindArgs := kind.VEX.Where(`"bf"."kind"`)
	held := append([]any{buildID, bun.List(visible)}, kindArgs...)
	var issues []int64
	if err := db.NewSelect().
		TableExpr(DecisionOccurrences).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		ColumnExpr(`"dv"."issue_id"`).
		Where(`"de"."product_id" = ?`, productID).
		Where(state, stateArgs...).
		Where(`"de"."live_key" IS NOT NULL`).
		Where(`"de"."visibility" IN (?)`, bun.List(visible)).
		Where(outcomes).
		Where(`EXISTS (SELECT 1 FROM "finding" AS "bf" WHERE "bf"."build_id" = ?
			AND "bf"."closed_at" IS NULL AND "bf"."visibility" IN (?) AND `+kinds+`
			AND `+DecisionOccurrenceOf("bf")+`)`, held...).
		GroupExpr(`"dv"."issue_id"`).
		Scan(ctx, &issues); err != nil {
		return nil, fmt.Errorf("read the issues decided in this product: %w", err)
	}
	return issues, nil
}

// issuesAtComponents is the open findings of one build of the issues given,
// at the visibilities given, one row per issue and component, with the
// component's name and stated package identifier. The component `c` and its
// consumer `uc` are joined for the decision to be matched against.
func issuesAtComponents(db bun.IDB, buildID int64, visible []access.Visibility,
	issues []int64) *bun.SelectQuery {

	kinds, kindArgs := kind.VEX.Where(`"f"."kind"`)
	byIssue, issueArgs := database.InAnyOf(`"f"."vulnerability_id"`, issues)
	return db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"c"."name" AS "component"`).
		ColumnExpr(`COALESCE(`+StatedPurl(`"f"."component_id"`)+`, "c"."purl", '') AS "purl"`).
		Where(`"f"."build_id" = ?`, buildID).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(kinds, kindArgs...).
		Where(byIssue, issueArgs...).
		GroupExpr(`"f"."vulnerability_id", "f"."build_id", "f"."component_id", "c"."name", "c"."purl"`)
}

// statementGroups regroups issues at components `p` into what one statement is
// about, keeping the groups whose every occurrence a decision answered, up to
// one past most.
func statementGroups(db bun.IDB, pairs *bun.SelectQuery, most int) *bun.SelectQuery {
	return db.NewSelect().
		TableExpr(`(?) AS "p"`, pairs).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "p"."vulnerability_id"`).
		ColumnExpr(`"p"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"v"."identifier" AS "identifier"`).
		ColumnExpr(`"p"."component" AS "component"`).
		ColumnExpr(`"p"."purl" AS "purl"`).
		GroupExpr(`"p"."vulnerability_id", "v"."identifier", "p"."component", "p"."purl"`).
		Having(`SUM("p"."decided") = SUM("p"."joined")`).
		Limit(int64(most + 1))
}
