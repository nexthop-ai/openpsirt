// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"context"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// TestASnapshotReadsWhatWasCommittedWhenItFirstRead pins the one view a read
// of many statements gets: a row a writer commits between two of them is
// not seen by the second, and the writer is not held up waiting for the read.
func TestASnapshotReadsWhatWasCommittedWhenItFirstRead(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		// A second connection for the writer: the harness gives SQLite one,
		// so a read outside a transaction hangs rather than passing.
		db.SetMaxOpenConns(max(db.Pool.MaxOpen, 2))
		t.Cleanup(func() { db.SetMaxOpenConns(db.Pool.MaxOpen) })
		scratchTable(t, db, "viewed", `"id" INTEGER PRIMARY KEY`)
		count := func(ctx context.Context, q bun.IDB) int {
			t.Helper()
			var n int
			if err := q.NewRaw(`SELECT COUNT(*) FROM "viewed"`).Scan(ctx, &n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if _, err := db.NewRaw(`INSERT INTO "viewed" ("id") VALUES (1)`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		err := database.Snapshot(ctx, db, func(ctx context.Context, view bun.IDB) error {
			if got := count(ctx, view); got != 1 {
				t.Errorf("the snapshot's first read saw %d rows", got)
			}
			// Written from outside while the snapshot is open, and committed:
			// on SQLite a snapshot holding the write lock would stall this
			// for the busy timeout.
			if err := database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
				_, err := tx.NewRaw(`INSERT INTO "viewed" ("id") VALUES (2)`).Exec(ctx)
				return err
			}); err != nil {
				t.Fatalf("a write while a snapshot was open failed: %v", err)
			}
			if got := count(ctx, view); got != 1 {
				t.Errorf("the snapshot saw a row committed after its first read: %d rows", got)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := count(ctx, db); got != 2 {
			t.Errorf("after the snapshot the table holds %d rows", got)
		}
	})
}
