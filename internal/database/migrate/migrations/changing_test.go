// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// servingBeside is a handle a serving instance would hold on the database db
// is migrating: a pool of its own on SQLite, whose harness gives the
// migration its one connection, and db's own pool on a server.
func servingBeside(t *testing.T, db *database.DB) *database.DB {
	t.Helper()
	if db.Server.Engine != database.SQLite {
		return db
	}
	var seq int
	var name, file string
	if err := db.QueryRowContext(t.Context(), `PRAGMA database_list`).Scan(&seq, &name, &file); err != nil {
		t.Fatal(err)
	}
	return dbtest.Open(t, "sqlite://"+file)
}

// An upgrade holds the schema change lock from before its first statement,
// through the notice it gives, to after its last; a serving instance sees the
// lock while the version is still the one it served, and the version moved
// once the lock is let go. An upgrade with nothing to apply never takes it.
func TestAnUpgradeHoldsTheChangeLockFromBeforeItsFirstStatement(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
		observer, err := migrate.NewObserver(ctx, servingBeside(t, db))
		if err != nil {
			t.Fatal(err)
		}
		expected, err := migrations.Expected()
		if err != nil {
			t.Fatal(err)
		}

		const notice = time.Second
		done := make(chan error, 1)
		go func() { done <- migrate.Up(context.WithoutCancel(ctx), db, quiet(), notice) }()
		deadline := time.Now().Add(30 * time.Second)
		for {
			changing, err := observer.Changing(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if changing {
				break
			}
			select {
			case err := <-done:
				t.Fatalf("the upgrade ended, answering %v, and no serving instance saw it changing the schema", err)
			default:
			}
			if time.Now().After(deadline) {
				t.Fatal("no serving instance saw the upgrade changing the schema within 30s")
			}
			time.Sleep(20 * time.Millisecond)
		}
		if applied, err := observer.Applied(ctx); err != nil || applied != v0120 {
			t.Errorf("as the change lock was taken the schema was at %d (%v), not %d", applied, err, v0120)
		}
		if err := <-done; err != nil {
			t.Fatalf("the upgrade: %v", err)
		}
		if changing, err := observer.Changing(ctx); err != nil || changing {
			t.Errorf("after the upgrade a serving instance saw the schema changing %v (%v)", changing, err)
		}
		if applied, err := observer.Applied(ctx); err != nil || applied != expected {
			t.Errorf("after the upgrade the schema was at %d (%v), not %d", applied, err, expected)
		}

		// Nothing to apply: the lock is never taken, though a notice is given.
		done = make(chan error, 1)
		go func() { done <- migrate.Up(context.WithoutCancel(ctx), db, quiet(), notice) }()
		for {
			changing, err := observer.Changing(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if changing {
				t.Fatal("an upgrade with nothing to apply took the schema change lock")
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("the upgrade with nothing to apply: %v", err)
				}
				return
			default:
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}
