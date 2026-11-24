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

// An upgrade holds the lease to change the schema from before its first
// statement, through the notice it gives and every migration's statements, to
// after its last; a serving instance sees it while the version is still the
// one it served, and the version moved once it is let go. An upgrade with
// nothing to apply never holds it to change the schema.
//
// The upgrade is the latest release's, run again over the schema it made
// with its version unrecorded, as a process ended between the two leaves it.
func TestAnUpgradeHoldsTheLeaseToChangeTheSchemaFromBeforeItsFirstStatement(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		unrecordLatest(t, db)
		observer := migrate.NewObserver(servingBeside(t, db))
		expected, err := migrations.Expected()
		if err != nil {
			t.Fatal(err)
		}

		look := func() (bool, int64, error) {
			change, applied, err := observer.Look(ctx, time.Minute, time.Minute)
			return change != migrate.Unchanged, applied, err
		}
		const notice = time.Second
		done := make(chan error, 1)
		go func() { done <- migrate.Up(context.WithoutCancel(ctx), db, quiet(), notice) }()
		deadline := time.Now().Add(30 * time.Second)
		for {
			if changing, _, err := look(); err == nil && changing {
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
		if _, applied, err := look(); err != nil || applied != expected-1 {
			t.Errorf("as the lease was held to change the schema, the schema was at %d (%v), not %d", applied, err, expected-1)
		}
		// Every look while the upgrade runs, its statements included, sees
		// the schema changing until the version is this build's.
		for watching := true; watching; {
			select {
			case err := <-done:
				done <- err
				watching = false
			default:
				if changing, applied, err := look(); err != nil || (!changing && applied < expected) {
					t.Fatalf("while the upgrade ran a serving instance saw changing %v at %d (%v)", changing, applied, err)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
		if err := <-done; err != nil {
			t.Fatalf("the upgrade: %v", err)
		}
		if changing, _, err := look(); err != nil || changing {
			t.Errorf("after the upgrade a serving instance saw the schema changing %v (%v)", changing, err)
		}
		if _, applied, err := look(); err != nil || applied != expected {
			t.Errorf("after the upgrade the schema was at %d (%v), not %d", applied, err, expected)
		}

		// Nothing to apply: the lease is never held to change the schema, though a
		// notice is given.
		done = make(chan error, 1)
		go func() { done <- migrate.Up(context.WithoutCancel(ctx), db, quiet(), notice) }()
		for {
			changing, _, err := look()
			if err != nil {
				t.Fatal(err)
			}
			if changing {
				t.Fatal("an upgrade with nothing to apply held the lease to change the schema")
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

// unrecordLatest takes away the record of the latest version applied to the
// latest schema the harness hands over, so the latest release's upgrade is
// outstanding over the schema it made.
func unrecordLatest(t *testing.T, db *database.DB) {
	t.Helper()
	expected, err := migrations.Expected()
	if err != nil {
		t.Fatal(err)
	}
	unrecordAt(t, db, expected)
}

// unrecordAt takes away the record of a version a schema at that version
// holds, so that release's upgrade is outstanding over the schema it made.
func unrecordAt(t *testing.T, db *database.DB, version int64) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), `DELETE FROM "`+migrate.VersionTable+`" WHERE "version_id" = ?`,
		version); err != nil {
		t.Fatal(err)
	}
	if applied, err := migrate.Version(t.Context(), db); err != nil || applied != version-1 {
		t.Fatalf("with version %d's record taken away the schema is at %d (%v), not %d",
			version, applied, err, version-1)
	}
}

// A record of an upgrade whose version the schema has reached pauses nobody,
// as a process ended after its last migration or a removal that failed leaves
// one, and a start with nothing to apply removes it. A record of an upgrade to
// a later version still pauses, and stays.
func TestARecordTheVersionHasReachedPausesNobody(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		// The harness hands over the latest schema, its records emptied.
		ctx := t.Context()
		expected, err := migrations.Expected()
		if err != nil {
			t.Fatal(err)
		}
		observer := migrate.NewObserver(servingBeside(t, db))
		record := func(target int64) {
			t.Helper()
			if _, err := db.ExecContext(ctx, `INSERT INTO "schema_change" ("started_at", "started_by", "target_version")
				VALUES (?, ?, ?)`, time.Now().UTC(), "a process", target); err != nil {
				t.Fatal(err)
			}
		}
		changing := func() bool {
			t.Helper()
			change, _, err := observer.Look(ctx, time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return change != migrate.Unchanged
		}
		count := func(where string) int {
			t.Helper()
			var n int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM "schema_change" WHERE "target_version" `+where,
				expected).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}

		record(expected)
		if changing() {
			t.Error("a record of an upgrade to the version applied paused a serving instance")
		}
		record(expected + 1)
		if !changing() {
			t.Error("a record of an upgrade to a later version paused nobody")
		}
		if err := migrate.Up(ctx, db, quiet(), 0); err != nil {
			t.Fatal(err)
		}
		if n := count("<= ?"); n != 0 {
			t.Errorf("a start with nothing to apply left %d records the version had reached", n)
		}
		if n := count("> ?"); n != 1 {
			t.Errorf("a start with nothing to apply left %d records of a later version, want 1", n)
		}
	})
}

// A release's upgrade committed with its version left unrecorded, as a process
// killed between the two leaves it, keeps every serving instance paused on
// every engine; the upgrade that records the version lets them go.
func TestAnUpgradeCommittedWithoutItsVersionKeepsInstancesPaused(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
		if err := migrations.RunV0130Unrecorded(ctx, db); err != nil {
			t.Fatal(err)
		}
		observer := migrate.NewObserver(servingBeside(t, db))
		look := func() (bool, int64) {
			t.Helper()
			change, applied, err := observer.Look(ctx, time.Minute, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return change == migrate.Recorded, applied
		}
		if changing, applied := look(); !changing || applied != v0120 {
			t.Errorf("after the upgrade committed unrecorded a serving instance saw changing %v at %d", changing, applied)
		}
		if err := migrate.Up(ctx, db, quiet(), 0); err != nil {
			t.Fatal(err)
		}
		if changing, _ := look(); changing {
			t.Error("after an upgrade recorded the version a serving instance still saw the schema changing")
		}
	})
}
