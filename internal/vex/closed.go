// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	findingkind "github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// closedGroup is one statement about findings of a build closed for one
// reason: an issue, a component by its name and stated package identifier, and
// the lowest finding of the group, which names the same row on every engine.
type closedGroup struct {
	VulnerabilityID int64
	Identifier      string
	Component       string
	Purl            string
	First           int64
}

// closedRow is a finding of a build closed for the reason asked, with what
// closed it.
type closedRow struct {
	ID              int64         `bun:"id"`
	VulnerabilityID int64         `bun:"vulnerability_id"`
	ComponentID     int64         `bun:"component_id"`
	Occurrence      string        `bun:"occurrence_identity"`
	Kind            string        `bun:"kind"`
	By              sql.NullInt64 `bun:"by"`
}

// heldRow is a finding of a build of an issue a closed finding is of, open or
// closed.
type heldRow struct {
	ID              int64  `bun:"id"`
	VulnerabilityID int64  `bun:"vulnerability_id"`
	ComponentID     int64  `bun:"component_id"`
	Occurrence      string `bun:"occurrence_identity"`
	Kind            string `bun:"kind"`
	Open            int    `bun:"open"`
}

// atComponent is an issue at one component.
type atComponent struct {
	issue     int64
	component int64
}

// atName is an issue at a component's name and package identifier.
type atName struct {
	issue int64
	name  string
	purl  string
}

// tally is what one issue at one component, or at one name and stated package
// identifier, gathers over its closed findings.
type tally struct {
	first     int64
	least     int64
	greatest  int64
	otherwise int
}

func (t *tally) add(o tally) {
	t.first = min(t.first, o.first)
	t.least = min(t.least, o.least)
	t.greatest = max(t.greatest, o.greatest)
	t.otherwise += o.otherwise
}

// closed is the findings of a build closed for the reason given that a
// statement is still made about, at the visibilities given, one group per
// issue, name and stated package identifier, up to one past the ceiling, so
// that reaching it is distinguishable from landing on it.
//
// A group is stated while the guards patched and disclaimed name hold.
//
// Read as sets: each statement reads one table by constants, joining another
// only by its primary key, and the groups are formed here. Asked of each row or
// group inside one statement, every engine has a plan that reads the build's
// findings or graph once per closed finding, and picks it on the statistics a
// bulk load leaves: past 30 s a read on PostgreSQL, MySQL and MariaDB, against
// under 0.35 s as sets, for one build of 84,000 findings.
func (s *Store) closed(ctx context.Context, buildID int64, visible []access.Visibility,
	because finding.Closure) ([]closedGroup, error) {

	rows, status, err := s.closedRows(ctx, buildID, visible, because)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	issues := make([]int64, 0, len(rows))
	for _, row := range rows {
		issues = append(issues, row.VulnerabilityID)
	}
	issues = distinct(issues)
	held, err := s.findingsOf(ctx, buildID, issues, because)
	if err != nil {
		return nil, err
	}
	if because == finding.Disclaimed {
		rows = latest(rows, held)
	}

	// Each issue at each component.
	pairs := map[atComponent]*tally{}
	components := make([]int64, 0, len(rows))
	for _, row := range rows {
		one := tally{first: row.ID, least: row.By.Int64, greatest: row.By.Int64}
		if because == finding.Disclaimed && status[row.By.Int64] != string(sbom.NotAffected) {
			one.otherwise = 1
		}
		at := atComponent{issue: row.VulnerabilityID, component: row.ComponentID}
		if have := pairs[at]; have != nil {
			have.add(one)
			continue
		}
		pairs[at] = &one
		components = append(components, row.ComponentID)
	}
	components = distinct(components)
	stated, err := finding.StatedPurls(ctx, s.idb(), buildID, components)
	if err != nil {
		return nil, err
	}
	named := slices.Clone(components)
	for _, row := range held {
		if row.Open == 1 {
			named = append(named, row.ComponentID)
		}
	}
	names, err := s.componentNames(ctx, distinct(named))
	if err != nil {
		return nil, err
	}
	// Asked of the name and the component's own package identifier, which may
	// be several components: one at a version a patch does not reach is
	// affected, and a statement naming both would say otherwise.
	openByName := map[atName]bool{}
	for _, row := range held {
		if row.Open == 1 {
			name := names[row.ComponentID]
			openByName[atName{issue: row.VulnerabilityID, name: name.name, purl: name.purl}] = true
		}
	}

	// Each issue, name and stated package identifier.
	groups := map[atName]*tally{}
	for at, pair := range pairs {
		purl, ships := stated[at.component]
		name := names[at.component]
		group := atName{issue: at.issue, name: name.name, purl: name.purl}
		if !ships || openByName[group] {
			continue
		}
		if purl.Valid {
			group.purl = purl.String
		}
		if have := groups[group]; have != nil {
			have.add(*pair)
			continue
		}
		one := *pair
		groups[group] = &one
	}
	stand := make([]atName, 0, len(groups))
	for group, t := range groups {
		// One supplier's statement and no other. Two suppliers answering
		// occurrences of one component each spoke for their own product, and the
		// format names the component once: credited to either, the document
		// says one of them spoke for the other's.
		//
		// And only a statement that said not affected, counted over every
		// statement closing an occurrence of the component: an upstream's
		// statement that a component is fixed closes occurrences too, and is not
		// a statement that it is unaffected.
		if because == finding.Disclaimed && (t.least != t.greatest || t.otherwise != 0) {
			continue
		}
		stand = append(stand, group)
	}
	slices.SortFunc(stand, func(a, b atName) int { return cmp.Compare(groups[a].first, groups[b].first) })
	if len(stand) > s.carrying()+1 {
		stand = stand[:s.carrying()+1]
	}

	named = named[:0]
	for _, group := range stand {
		named = append(named, group.issue)
	}
	identifiers, err := s.identifiers(ctx, distinct(named))
	if err != nil {
		return nil, err
	}
	out := make([]closedGroup, 0, len(stand))
	for _, group := range stand {
		out = append(out, closedGroup{
			VulnerabilityID: group.issue, Identifier: identifiers[group.issue],
			Component: group.name, Purl: group.purl, First: groups[group].first,
		})
	}
	return out, nil
}

// closedRows is the findings of a build closed for the reason given at the
// visibilities given whose closure still stands, and for a supplier's
// statement what each statement said.
func (s *Store) closedRows(ctx context.Context, buildID int64, visible []access.Visibility,
	because finding.Closure) ([]closedRow, map[int64]string, error) {

	by := `"f"."suppressed_by"`
	if because == finding.Disclaimed {
		by = `"f"."stated_by"`
	}
	kinds, kindArgs := findingkind.VEX.Where(`"f"."kind"`)
	var rows []closedRow
	if err := s.idb().NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."id", "f"."vulnerability_id", "f"."component_id", "f"."occurrence_identity", "f"."kind"`).
		ColumnExpr(by+` AS "by"`).
		Where(`"f"."build_id" = ?`, buildID).
		Where(`"f"."closed_because" = ?`, because).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(kinds, kindArgs...).
		Scan(ctx, &rows); err != nil {
		return nil, nil, fmt.Errorf("read the findings closed as %s: %w", because, err)
	}
	closures := make([]int64, 0, len(rows))
	for _, row := range rows {
		if row.By.Valid {
			closures = append(closures, row.By.Int64)
		}
	}
	if len(closures) == 0 {
		return nil, nil, nil
	}
	byID, args := database.InAnyOf(`"id"`, distinct(closures))
	var standing []struct {
		ID     int64  `bun:"id"`
		Status string `bun:"status"`
	}
	q := s.idb().NewSelect().TableExpr(`"suppression"`).ColumnExpr(`"id", '' AS "status"`).
		Where(`"closed_scan_id" IS NULL`)
	if because == finding.Disclaimed {
		q = s.idb().NewSelect().TableExpr(`"received_vex_statement"`).ColumnExpr(`"id", "status"`).
			Where(`"superseded_at" IS NULL`)
	}
	if err := q.Where(byID, args...).Scan(ctx, &standing); err != nil {
		return nil, nil, fmt.Errorf("read what closed the findings closed as %s: %w", because, err)
	}
	status := make(map[int64]string, len(standing))
	for _, row := range standing {
		status[row.ID] = row.Status
	}
	kept := rows[:0]
	for _, row := range rows {
		if _, stands := status[row.By.Int64]; row.By.Valid && stands {
			kept = append(kept, row)
		}
	}
	return kept, status, nil
}

// findingsOf is the findings of a build of the issues given at the kinds a VEX
// document states. For the build's patches, the open ones, one per issue and
// component; for suppliers' statements every one, which latest needs as well.
//
// Read at every visibility, whatever the document is read at: an undisclosed
// occurrence still open holds back a disclosed statement, which would otherwise
// say fixed or not affected about a component the build has open.
func (s *Store) findingsOf(ctx context.Context, buildID int64, issues []int64,
	because finding.Closure) ([]heldRow, error) {

	kinds, kindArgs := findingkind.VEX.Where(`"f"."kind"`)
	byIssue, args := database.InAnyOf(`"f"."vulnerability_id"`, issues)
	q := s.idb().NewSelect().
		TableExpr(`"finding" AS "f"`).
		Where(`"f"."build_id" = ?`, buildID).
		Where(kinds, kindArgs...).
		Where(byIssue, args...)
	if because == finding.Disclaimed {
		q = q.ColumnExpr(`"f"."id", "f"."vulnerability_id", "f"."component_id", "f"."occurrence_identity", "f"."kind"`).
			ColumnExpr(`CASE WHEN "f"."closed_at" IS NULL THEN 1 ELSE 0 END AS "open"`)
	} else {
		q = q.ColumnExpr(`"f"."vulnerability_id", "f"."component_id", 1 AS "open"`).
			Where(`"f"."closed_at" IS NULL`).
			GroupExpr(`"f"."vulnerability_id", "f"."component_id"`)
	}
	var rows []heldRow
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the findings of the issues closed in this build: %w", err)
	}
	return rows, nil
}

// latest keeps the closed rows that are the latest row of their kind and issue
// at their occurrence, as finding.latestAtItsOccurrence asks it, over every
// row held of their issues.
//
// A run records a new row rather than reopening a closed one, so the later row,
// patched by the build or open again, is what the document goes by.
func latest(rows []closedRow, held []heldRow) []closedRow {
	type at struct {
		issue      int64
		occurrence string
		kind       string
	}
	last := make(map[at]int64, len(held))
	for _, row := range held {
		k := at{row.VulnerabilityID, row.Occurrence, row.Kind}
		last[k] = max(last[k], row.ID)
	}
	kept := rows[:0]
	for _, row := range rows {
		if last[at{row.VulnerabilityID, row.Occurrence, row.Kind}] <= row.ID {
			kept = append(kept, row)
		}
	}
	return kept
}

// componentName is a component's name and its own package identifier, empty
// where it has none.
type componentName struct {
	name string
	purl string
}

func (s *Store) componentNames(ctx context.Context, ids []int64) (map[int64]componentName, error) {
	byID, args := database.InAnyOf(`"c"."id"`, ids)
	var rows []struct {
		ID   int64          `bun:"id"`
		Name string         `bun:"name"`
		Purl sql.NullString `bun:"purl"`
	}
	if err := s.idb().NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`"c"."id", "c"."name", "c"."purl"`).
		Where(byID, args...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the components closed findings are at: %w", err)
	}
	names := make(map[int64]componentName, len(rows))
	for _, row := range rows {
		names[row.ID] = componentName{name: row.Name, purl: row.Purl.String}
	}
	return names, nil
}

func (s *Store) identifiers(ctx context.Context, issues []int64) (map[int64]string, error) {
	byID, args := database.InAnyOf(`"v"."id"`, issues)
	var rows []struct {
		ID         int64  `bun:"id"`
		Identifier string `bun:"identifier"`
	}
	if err := s.idb().NewSelect().
		TableExpr(`"vulnerability" AS "v"`).
		ColumnExpr(`"v"."id", "v"."identifier"`).
		Where(byID, args...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the names of the issues closed: %w", err)
	}
	identifiers := make(map[int64]string, len(rows))
	for _, row := range rows {
		identifiers[row.ID] = row.Identifier
	}
	return identifiers, nil
}

// distinct is the identifiers given, each once, in order.
func distinct(ids []int64) []int64 {
	slices.Sort(ids)
	return slices.Compact(ids)
}
