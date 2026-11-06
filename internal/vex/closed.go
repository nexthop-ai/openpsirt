// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

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
	ClosedAt        time.Time     `bun:"closed_at"`
}

// heldRow is a finding of a build of an issue a closed finding is of, open or
// closed.
type heldRow struct {
	VulnerabilityID int64 `bun:"vulnerability_id"`
	ComponentID     int64 `bun:"component_id"`
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
	held, err := s.openOf(ctx, buildID, distinct(issues))
	if err != nil {
		return nil, err
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
		named = append(named, row.ComponentID)
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
		name := names[row.ComponentID]
		openByName[atName{issue: row.VulnerabilityID, name: name.name, purl: name.purl}] = true
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
//
// Grouped in the statement, so an occurrence closed again and again reaches
// the application once per closure rather than once per row: for the patches
// the lowest row at each issue, component and patch, which dates the
// statement; for the suppliers' statements the highest at each occurrence,
// component and statement, of which latest keeps the one still the latest.
// Every row of their issues read into the application, the suppliers'
// statements take 2.2 s against 0.46 s with 50 rows at each closed occurrence
// on SQLite.
//
// Grouped by the closure first: no index leads with it, so no engine walks an
// index for the grouping's order. Led by the issue, SQLite with statistics
// walks the occurrence index over the whole table: 1.6 s against 0.3 s.
//
// Every closing sets the closing time with its reason, so the closed findings
// are named as such: the build's closed rows are then one range of an index
// leading with the build. Left out, MariaDB on the statistics a bulk load
// leaves reads the whole table, 193 ms against 28 ms with eleven builds
// holding the build's findings.
func (s *Store) closedRows(ctx context.Context, buildID int64, visible []access.Visibility,
	because finding.Closure) ([]closedRow, map[int64]string, error) {

	kinds, kindArgs := findingkind.VEX.Where(`"f"."kind"`)
	var rows []closedRow
	q := s.idb().NewSelect().
		TableExpr(`"finding" AS "f"`).
		Where(`"f"."closed_because" = ?`, because).
		Where(`"f"."closed_at" IS NOT NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible))
	if because == finding.Patched {
		q = q.ColumnExpr(`MIN("f"."id") AS "id", "f"."vulnerability_id", "f"."component_id"`).
			ColumnExpr(`"f"."suppressed_by" AS "by"`).
			Where(`"f"."build_id" = ?`, buildID).
			Where(kinds, kindArgs...).
			GroupExpr(`"f"."suppressed_by", "f"."vulnerability_id", "f"."component_id"`)
	} else {
		q = q.ColumnExpr(`MAX("f"."id") AS "id", "f"."vulnerability_id", "f"."component_id"`).
			ColumnExpr(`"f"."occurrence_identity", "f"."kind", "f"."stated_by" AS "by"`).
			ColumnExpr(`MAX("f"."closed_at") AS "closed_at"`).
			Where(`"f"."build_id" = ?`, buildID).
			Where(kinds, kindArgs...).
			GroupExpr(`"f"."stated_by", "f"."kind", "f"."vulnerability_id", "f"."occurrence_identity", "f"."component_id"`)
	}
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, nil, fmt.Errorf("read the findings closed as %s: %w", because, err)
	}
	if because == finding.Disclaimed {
		var err error
		if rows, err = s.latest(ctx, buildID, rows); err != nil {
			return nil, nil, err
		}
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
	q = s.idb().NewSelect().TableExpr(`"suppression"`).ColumnExpr(`"id", '' AS "status"`).
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

// openOf is the open findings of a build of the issues given at the kinds a
// VEX document states, one per issue and component.
//
// Read at every visibility, whatever the document is read at: an undisclosed
// occurrence still open holds back a disclosed statement, which would otherwise
// say fixed or not affected about a component the build has open. Every
// visibility is named all the same, so the read is the build's own open rows of
// each issue in the index leading with the build; left out, MySQL and MariaDB
// read each issue's open rows of every build holding it, 55 ms against 10 ms on
// MySQL with eleven builds holding the issues.
func (s *Store) openOf(ctx context.Context, buildID int64, issues []int64) ([]heldRow, error) {
	kinds, kindArgs := findingkind.VEX.Where(`"f"."kind"`)
	byIssue, args := database.InAnyOf(`"f"."vulnerability_id"`, issues)
	var rows []heldRow
	if err := s.idb().NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."vulnerability_id", "f"."component_id"`).
		Where(`"f"."build_id" = ?`, buildID).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(access.Visibilities())).
		Where(kinds, kindArgs...).
		Where(byIssue, args...).
		GroupExpr(`"f"."vulnerability_id", "f"."component_id"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the findings of the issues closed in this build: %w", err)
	}
	return rows, nil
}

// latest keeps the closed rows that are the latest row of their kind and issue
// at their occurrence in the build, as the decidable findings ask it, in the
// order finding.Later gives.
//
// Only the last of the rows given at an occurrence can be, so the rows after
// it at each such occurrence are read, and an occurrence holding any is
// dropped. Only rows recorded after it are asked, which keeps each term one
// range of the occurrence index: a row recorded earlier and closed later is a
// replacement's row a check's match was written after, and both are among the
// rows given. A run records a new row rather than reopening a closed one, so an
// occurrence closed and closed again holds a row per closing; asked by
// identifier from the highest row up, the read never sees that history.
//
// Read as a set, the occurrences named a bounded number at a time, so MySQL and
// MariaDB cost each list by looking in the index rather than from statistics.
// Asked of each row, MySQL and MariaDB on the statistics a bulk load leaves
// read the build's whole open index once per row: past 30 s for 2,678 rows with
// 50 rows at each closed occurrence.
//
// Each term names the build, and nothing stands outside the terms: each is
// then one range of the occurrence index, which carries the build, the kind
// and the row. With the build asked once outside them, SQLite with no
// statistics reads the build's whole index once per statement, 5 s each with
// 50 rows at each closed occurrence.
func (s *Store) latest(ctx context.Context, buildID int64, rows []closedRow) ([]closedRow, error) {
	last := make(map[atOccurrence]closedRow, len(rows))
	for _, row := range rows {
		k := atOccurrence{row.VulnerabilityID, row.Occurrence, row.Kind}
		if have, ok := last[k]; !ok || have.ClosedAt.Before(row.ClosedAt) ||
			(have.ClosedAt.Equal(row.ClosedAt) && have.ID < row.ID) {
			last[k] = row
		}
	}
	asked := make([]atOccurrence, 0, len(last))
	for k := range last {
		asked = append(asked, k)
	}
	later := map[atOccurrence]bool{}
	for start := 0; start < len(asked); start += occurrencesAsked {
		at := asked[start:min(start+occurrencesAsked, len(asked))]
		terms := make([]string, 0, len(at))
		args := make([]any, 0, 5*len(at))
		for _, k := range at {
			terms = append(terms, `("lt"."occurrence_identity" = ? AND "lt"."vulnerability_id" = ? AND "lt"."build_id" = ? AND "lt"."kind" = ? AND "lt"."id" > ? AND `+
				finding.Later("lt", "?", "?")+`)`)
			args = append(args, k.occurrence, k.issue, buildID, k.kind, last[k].ID,
				last[k].ClosedAt, last[k].ClosedAt, last[k].ID)
		}
		var after []struct {
			VulnerabilityID int64  `bun:"vulnerability_id"`
			Occurrence      string `bun:"occurrence_identity"`
			Kind            string `bun:"kind"`
		}
		if err := s.idb().NewSelect().
			TableExpr(`"finding" AS "lt"`).
			ColumnExpr(`"lt"."vulnerability_id", "lt"."occurrence_identity", "lt"."kind"`).
			Where(strings.Join(terms, " OR "), args...).
			GroupExpr(`"lt"."kind", "lt"."vulnerability_id", "lt"."occurrence_identity"`).
			Scan(ctx, &after); err != nil {
			return nil, fmt.Errorf("read the rows after the closed findings at their occurrences: %w", err)
		}
		for _, row := range after {
			later[atOccurrence{row.VulnerabilityID, row.Occurrence, row.Kind}] = true
		}
	}
	kept := make([]closedRow, 0, len(last))
	for _, row := range rows {
		k := atOccurrence{row.VulnerabilityID, row.Occurrence, row.Kind}
		if last[k].ID == row.ID && !later[k] {
			kept = append(kept, row)
		}
	}
	return kept, nil
}

// atOccurrence is an issue at an occurrence, in findings of one kind.
type atOccurrence struct {
	issue      int64
	occurrence string
	kind       string
}

// occurrencesAsked is how many occurrences one read of the latest rows names:
// at most what MySQL and MariaDB cost by looking in the index, 200 ranges by
// default, past which they cost a list from statistics.
const occurrencesAsked = 200

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
