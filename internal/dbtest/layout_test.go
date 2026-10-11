// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// leases is how many rows a layout test loads: enough pages that a table
// holding a deleted copy beside a live one is told apart from one that is not.
const leases = 5000

// loadLeases writes leases rows to the lease table in the order of their
// names, each name beginning with prefix. The table points at nothing, so it
// fills without a world.
func loadLeases(ctx context.Context, t *testing.T, db *database.DB, prefix string) {
	t.Helper()
	const batch = 500
	for start := 0; start < leases; start += batch {
		values := make([]string, batch)
		args := make([]any, batch)
		for i := range batch {
			values[i] = "(?)"
			args[i] = fmt.Sprintf("%s-%07d", prefix, start+i)
		}
		if _, err := db.ExecContext(ctx,
			`INSERT INTO "lease" ("name") VALUES `+strings.Join(values, ", "), args...); err != nil {
			t.Fatalf("load leases: %v", err)
		}
	}
}

// settled loads the lease table, analyzes it and reads its layout.
func settled(ctx context.Context, t *testing.T, db *database.DB, prefix string) layout {
	t.Helper()
	loadLeases(ctx, t, db, prefix)
	if err := analyze(ctx, db, "lease"); err != nil {
		t.Fatal(err)
	}
	l, err := readLayout(ctx, db, "lease")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestALoadedAnalyzedTableIsReportedWithItsPages(t *testing.T) {
	Servers(t, func(t *testing.T, db *database.DB) {
		l := settled(t.Context(), t, db, "a")
		if l.pages == 0 {
			t.Fatalf("%d leases were loaded and the layout reports no pages: %s", leases, l)
		}
	})
}

func TestATableTheSchemaDoesNotMakeIsRefusedRatherThanReported(t *testing.T) {
	Servers(t, func(t *testing.T, db *database.DB) {
		if l, err := readLayout(t.Context(), db, "no_such_table"); err == nil {
			t.Fatalf("a table that is not there was reported as %s", l)
		}
	})
}

// PostgreSQL alone: it is the one engine keeping a correlation, and the one
// engine whose statistics outlive a truncation.
func TestATableNotAnalyzedSinceItWasEmptiedIsRefusedRatherThanReported(t *testing.T) {
	Only(t, database.Postgres, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		settled(ctx, t, db, "a")
		if err := fresh(ctx, db); err != nil {
			t.Fatal(err)
		}
		if l, err := readLayout(ctx, db, "lease"); err == nil {
			t.Fatalf("an emptied table was reported from the statistics of the rows "+
				"it held before: %s", l)
		}
	})
}

// The delete in the middle is the control: it is the ordinary emptying, and a
// reload after it has to be told apart, or the two fresh loads agreeing says
// nothing. Each load names its rows differently, so no reload writes over a
// deleted row with the same key.
//
// PostgreSQL alone. On MySQL and MariaDB the pages a reload after a delete
// takes depend on whether the server has yet purged the deleted rows, which a
// test of this size races, so the control cannot be relied on to differ.
func TestAMeasurementReloadsIntoTheLayoutAFreshLoadLeaves(t *testing.T) {
	Only(t, database.Postgres, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if err := fresh(ctx, db); err != nil {
			t.Fatal(err)
		}
		first := settled(ctx, t, db, "a")

		if err := clear(ctx, db); err != nil {
			t.Fatal(err)
		}
		deleted := settled(ctx, t, db, "b")
		if deleted.pages <= first.pages {
			t.Fatalf("a reload after a delete took %d pages and a fresh load %d, so this "+
				"cannot tell the two apart", deleted.pages, first.pages)
		}

		// Deleted first, so the table is empty and its dead rows are not: a
		// measurement's emptying that passed over an empty table would leave
		// them, and the reload would take more pages.
		if err := clear(ctx, db); err != nil {
			t.Fatal(err)
		}
		if err := fresh(ctx, db); err != nil {
			t.Fatal(err)
		}
		again := settled(ctx, t, db, "c")
		if again.pages != first.pages {
			t.Errorf("a reload after a measurement's emptying took %d pages, and a fresh "+
				"load %d", again.pages, first.pages)
		}
		if len(again.order) != 1 || again.order[0].column != "name" || again.order[0].value < 0.99 {
			t.Errorf("leases loaded in name order after a measurement's emptying read as %s", again)
		}
	})
}

// MySQL and MariaDB truncate with the session's foreign key checks suspended.
// The pool is narrowed to one connection, so the insert after the emptying
// runs on the connection that emptied.
func TestAMeasurementsEmptyingLeavesEveryTableEmptyAndForeignKeysEnforced(t *testing.T) {
	Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { db.SetMaxOpenConns(db.Pool.MaxOpen) })

		loadLeases(ctx, t, db, "a")
		if err := fresh(ctx, db); err != nil {
			t.Fatal(err)
		}
		var held int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "lease"`).Scan(&held); err != nil {
			t.Fatal(err)
		}
		if held != 0 {
			t.Errorf("%d leases survived a measurement's emptying", held)
		}

		_, err := db.ExecContext(ctx, `INSERT INTO "patch_commit"
			("repository_id", "commit_hash", "found", "branch_count", "created_at")
			VALUES (?, ?, ?, ?, ?)`, 1, "0123456789abcdef", true, 0, time.Now().UTC())
		if err == nil {
			t.Fatal("a commit naming a repository nobody holds was written after a " +
				"measurement's emptying, so foreign keys went unchecked")
		}
	})
}
