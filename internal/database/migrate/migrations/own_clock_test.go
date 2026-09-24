// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// ownClock is the migration that clocks a recorded flaw from its first
// severity and marks a report found here.
const ownClock = 38

// A v0.2.0 database's recorded flaws come across clocked from when they were
// first rated, in whatever way they were, on the windows for our own products;
// one rated in no way loses its deadline; one no report is the record of loses
// its disclosure date; and a scanned finding is left as it was.
func TestAV020DatabaseMovesItsRecordedFlawsOntoTheirOwnClock(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v020)
		tables := columns(t, ctx, db)

		made := map[string]bool{}
		for _, table := range []string{"finding", "flaw_report", "issue_rating"} {
			fillOne(t, ctx, db, tables, table, made)
		}
		t0 := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)
		due := t0.Add(24 * time.Hour)
		disclose := t0.Add(90 * 24 * time.Hour)

		// Four issues: rated as published, rated only by this product, rated
		// by nobody, and one a scanner reported.
		exec(t, ctx, db, `UPDATE "vulnerability" SET "identifier" = 'SONIC-2026-100001',
			"identifier_folded" = 'sonic-2026-100001', "severity" = 'high' WHERE "id" = 1`)
		for id, severity := range map[int64]string{2: "", 3: "", 4: "high"} {
			name := []string{"", "", "SONIC-2026-100002", "SONIC-2026-100003", "CVE-2026-4444"}[id]
			copyRow(t, ctx, db, tables["vulnerability"], "vulnerability", map[string]any{
				"identifier": name, "identifier_folded": strings.ToLower(name), "severity": severity})
		}
		exec(t, ctx, db, `UPDATE "issue_rating" SET "vulnerability_id" = 2, "severity" = 'critical',
			"product_id" = 1`)
		// The report is the record of issue 1, which a reporter sent.
		exec(t, ctx, db, `UPDATE "flaw_report" SET "vulnerability_id" = 1`)

		exec(t, ctx, db, `UPDATE "finding" SET "vulnerability_id" = 1, "kind" = 'entered',
			"opened_at" = ?, "closed_at" = NULL, "due_at" = ?, "disclose_at" = ?,
			"urgency_exploited" = ?, "exploited_learned_at" = NULL, "place_identity" = 'a'`,
			t0, due, disclose, false)
		later := t0.Add(5 * 24 * time.Hour)
		for _, row := range []map[string]any{
			// Issue 1 again, in a build recorded five days later.
			{"vulnerability_id": int64(1), "opened_at": later, "place_identity": "b"},
			{"vulnerability_id": int64(2), "opened_at": later, "place_identity": "c"},
			{"vulnerability_id": int64(3), "opened_at": later, "place_identity": "d"},
			{"vulnerability_id": int64(4), "opened_at": later, "place_identity": "e", "kind": "vulnerability"},
		} {
			copyRow(t, ctx, db, tables["finding"], "finding", row)
		}

		dbtest.MigrateTo(t, db, ownClock)

		type got struct {
			Issue      int64      `bun:"vulnerability_id"`
			Place      string     `bun:"place_identity"`
			RatedAt    *time.Time `bun:"rated_at"`
			DueAt      *time.Time `bun:"due_at"`
			DiscloseAt *time.Time `bun:"disclose_at"`
		}
		var rows []got
		if err := db.NewRaw(`SELECT "vulnerability_id", "place_identity", "rated_at", "due_at",
			"disclose_at" FROM "finding" ORDER BY "place_identity"`).Scan(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 5 {
			t.Fatalf("%d findings came across, want 5", len(rows))
		}
		same := func(a *time.Time, b time.Time) bool { return a != nil && a.Equal(b) }
		for _, row := range rows {
			switch row.Place {
			case "a", "b":
				// Rated as published, so from the first recording, on the
				// window for a high.
				if !same(row.RatedAt, t0) || !same(row.DueAt, t0.Add(90*24*time.Hour)) {
					t.Errorf("issue 1 at %s: rated %v, due %v; want both counted from %v",
						row.Place, row.RatedAt, row.DueAt, t0)
				}
				if row.DiscloseAt == nil {
					t.Errorf("issue 1 at %s, reported from outside, lost its disclosure date", row.Place)
				}
			case "c":
				// Rated critical by this product alone.
				if !same(row.RatedAt, later) || !same(row.DueAt, later.Add(30*24*time.Hour)) {
					t.Errorf("issue 2: rated %v, due %v; want both counted from %v",
						row.RatedAt, row.DueAt, later)
				}
				if row.DiscloseAt != nil {
					t.Errorf("issue 2, with no report, kept a disclosure date %v", row.DiscloseAt)
				}
			case "d":
				if row.RatedAt != nil || row.DueAt != nil {
					t.Errorf("issue 3, rated by nobody: rated %v, due %v; want neither",
						row.RatedAt, row.DueAt)
				}
			case "e":
				if row.RatedAt != nil || !same(row.DueAt, due) || !same(row.DiscloseAt, disclose) {
					t.Errorf("the scanned finding moved: rated %v, due %v, disclosed %v",
						row.RatedAt, row.DueAt, row.DiscloseAt)
				}
			}
		}
		var foundHere int
		if err := db.NewRaw(`SELECT COUNT(*) FROM "flaw_report" WHERE "found_here" = ?`, true).
			Scan(ctx, &foundHere); err != nil {
			t.Fatal(err)
		}
		if foundHere != 0 {
			t.Errorf("%d reports came across as found here; every v0.2.0 report came from outside", foundHere)
		}

		// Rolled back, the columns go; applied again, they return.
		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll back: %v", err)
		}
		for table, column := range map[string]string{"finding": "rated_at", "flaw_report": "found_here"} {
			for _, c := range columns(t, ctx, db)[table] {
				if c.name == column {
					t.Errorf("rolled back, %s still has %s", table, column)
				}
			}
		}
		dbtest.MigrateTo(t, db, ownClock)
		dbtest.Reset(t, db)
		if err := schema.Up(ctx, db, quiet()); err != nil {
			t.Fatalf("migrate to the latest: %v", err)
		}
	})
}

// fillOne writes one row into a table, and first into every table it has to
// point at. A reference that may be empty is left empty, so only what the
// table needs is written.
func fillOne(t *testing.T, ctx context.Context, db *database.DB, tables map[string][]column,
	name string, made map[string]bool) {
	t.Helper()
	if made[name] {
		return
	}
	cols, ok := tables[name]
	if !ok {
		t.Fatalf("no table %s", name)
	}
	for _, c := range cols {
		if c.refers != "" && c.refers != name && !c.nullable {
			fillOne(t, ctx, db, tables, c.refers, made)
		}
	}
	when := time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC)
	var names, marks []string
	var args []any
	for i, c := range cols {
		if c.generated {
			continue
		}
		names = append(names, `"`+c.name+`"`)
		marks = append(marks, "?")
		if c.refers != "" && c.nullable {
			args = append(args, nil)
			continue
		}
		args = append(args, valueFor(name, c, i, when))
	}
	exec(t, ctx, db, `INSERT INTO "`+name+`" (`+strings.Join(names, ", ")+`) VALUES (`+
		strings.Join(marks, ", ")+`)`, args...)
	made[name] = true
}
