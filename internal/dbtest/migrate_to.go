// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"io"
	"log/slog"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// MigrateTo applies the migrations up to and including a version, which is
// how a test builds the schema a release shipped.
//
// Through the runner a deployment uses, with its lock. A migration registered
// without the library's transaction opens connections of its own, and on a
// pool of one connection, which is what the harness gives SQLite, a runner that
// keeps one for itself waits on that migration for ever.
func MigrateTo(t *testing.T, db *database.DB, version int64) {
	t.Helper()
	if err := migrate.UpTo(t.Context(), db, slog.New(slog.NewTextHandler(io.Discard, nil)),
		version); err != nil {
		t.Fatalf("apply the migrations up to %d: %v", version, err)
	}
}

// Empty drops every table this tree's schema holds, and the record of which
// migrations were applied, so the database can be migrated up to an earlier
// release's schema. A database is only ever upgraded, so this is the way a
// test reaches one.
//
// The database is migrated to the latest first, so every table in the list is
// there to drop, and back to the latest when the test ends, so the next test
// finds the schema it expects whatever this one left.
func Empty(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() {
		if err := migrate.Up(context.WithoutCancel(ctx), db, quiet); err != nil {
			t.Errorf("migrate back to the latest: %v", err)
		}
	})
	if err := migrate.Up(ctx, db, quiet); err != nil {
		t.Fatalf("migrate to the latest: %v", err)
	}
	// Children before the rows they reference, which is the order the list
	// keeps for deleting, and the order the engines that enforce foreign keys
	// on a drop need.
	for _, table := range append(slices.Clone(tables), "goose_db_version") {
		if _, err := db.ExecContext(ctx, `DROP TABLE "`+table+`"`); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}
}
