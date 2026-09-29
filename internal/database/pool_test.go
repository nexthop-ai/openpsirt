// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
)

func TestIdleConnectionsAreReaped(t *testing.T) {
	// The whole defense rests on this: a connection must be closed by us
	// before anything in the path kills it behind our back. Asserting the
	// setting was applied would prove nothing, so this checks the pool's own
	// count of connections it closed for being idle too long.
	for name, env := range map[database.Engine]string{
		database.Postgres: dbtest.PostgresURLEnv,
		database.MySQL:    dbtest.MySQLURLEnv,
		database.MariaDB:  dbtest.MariaDBURLEnv,
	} {
		t.Run(string(name), func(t *testing.T) {
			// Before the URL is read, not after: a configured engine this run
			// was told to leave alone is one this test must not connect to.
			engines.SkipUnless(t, name)
			url := os.Getenv(env)
			if url == "" {
				t.Skipf("%s is not set", env)
			}
			target, err := database.ParseURL(url)
			if err != nil {
				t.Fatal(err)
			}
			db, err := database.OpenWithPool(t.Context(), target, database.Pool{
				MaxOpen: 4, MaxIdle: 4,
				IdleTimeout: 200 * time.Millisecond,
				Lifetime:    time.Hour,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()

			// Open several at once so more than one lands in the pool.
			var wg sync.WaitGroup
			for range 4 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					var n int
					_ = db.QueryRowContext(t.Context(), "SELECT 1").Scan(&n)
					time.Sleep(50 * time.Millisecond)
				}()
			}
			wg.Wait()

			// Wait for the reaper. Go runs its cleaner on a timer with a
			// one-second floor, however short the idle timeout is — so a
			// shorter wait than that proves nothing either way.
			deadline := time.Now().Add(10 * time.Second)
			var stats sql.DBStats
			for time.Now().Before(deadline) {
				time.Sleep(250 * time.Millisecond)
				stats = db.Stats()
				if stats.MaxIdleTimeClosed > 0 {
					break
				}
			}
			if stats.MaxIdleTimeClosed == 0 {
				t.Errorf("no connection was closed for being idle: %+v", stats)
			}
			t.Logf("%s: closed %d idle connections, %d still open",
				name, stats.MaxIdleTimeClosed, stats.OpenConnections)
		})
	}
}

func TestPoolIsBounded(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if db.Server.Engine == database.SQLite {
			t.Skip("the harness holds SQLite to one connection; TestSQLitePoolIsAsWideAsConfigured covers it")
		}
		got := db.Stats().MaxOpenConnections
		want := database.DefaultPool().MaxOpen
		if got != want {
			t.Errorf("%s: max open connections is %d, want %d", db.Server.Engine, got, want)
		}
	})
}

// sqliteFile opens a SQLite database in a file of the test's own, with the
// pool a deployment gets rather than the harness's single connection.
func sqliteFile(t *testing.T) *database.DB {
	t.Helper()
	target, err := database.ParseURL("sqlite://" + filepath.Join(t.TempDir(), "pool.db"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.OpenWithPool(t.Context(), target, database.DefaultPool())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(),
		`CREATE TABLE "counter" ("id" INTEGER PRIMARY KEY, "n" INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `INSERT INTO "counter" ("id", "n") VALUES (1, 0)`); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestSQLitePoolIsAsWideAsConfigured(t *testing.T) {
	if got, want := sqliteFile(t).Stats().MaxOpenConnections, database.DefaultPool().MaxOpen; got != want {
		t.Errorf("a SQLite file has %d connections at most, want %d", got, want)
	}

	target, err := database.ParseURL("sqlite://:memory:")
	if err != nil {
		t.Fatal(err)
	}
	memory, err := database.OpenWithPool(t.Context(), target, database.DefaultPool())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = memory.Close() }()
	if got := memory.Stats().MaxOpenConnections; got != 1 {
		t.Errorf("an in-memory SQLite database has %d connections at most, want 1: "+
			"every connection to one opens a database of its own", got)
	}
}

func TestSQLiteReadsWhileAWriteTransactionIsOpen(t *testing.T) {
	db := sqliteFile(t)
	ctx := t.Context()

	holding := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
			if _, err := tx.ExecContext(ctx, `UPDATE "counter" SET "n" = 1 WHERE "id" = 1`); err != nil {
				return err
			}
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding

	read, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var n int
	err := db.QueryRowContext(read, `SELECT "n" FROM "counter" WHERE "id" = 1`).Scan(&n)
	close(release)
	if err != nil {
		t.Fatalf("a read waited on an open write transaction: %v", err)
	}
	if n != 0 {
		t.Errorf("a read saw %d, a write that had not committed", n)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSQLiteWriteTransactionsTakeTurns(t *testing.T) {
	// Two transactions each read the counter and write it back one higher.
	// Both are begun directly rather than through the retrying helper, which
	// would hide the failure this pins: a second transaction begun deferred
	// reads while the first is open, finds its snapshot stale once the first
	// commits, and fails at once instead of waiting.
	db := sqliteFile(t)
	ctx := t.Context()
	increment := func(tx bun.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT "n" FROM "counter" WHERE "id" = 1`).Scan(&n); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE "counter" SET "n" = ? WHERE "id" = 1`, n+1)
		return err
	}

	first, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := first.QueryRowContext(ctx, `SELECT "n" FROM "counter" WHERE "id" = 1`).Scan(&n); err != nil {
		t.Fatal(err)
	}

	begun := make(chan struct{})
	second := make(chan error, 1)
	go func() {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			second <- err
			return
		}
		var seen int
		if err := tx.QueryRowContext(ctx, `SELECT "n" FROM "counter" WHERE "id" = 1`).Scan(&seen); err != nil {
			_ = tx.Rollback()
			second <- err
			return
		}
		close(begun)
		if err := increment(tx); err != nil {
			_ = tx.Rollback()
			second <- err
			return
		}
		second <- tx.Commit()
	}()

	// Long enough for a second transaction that does not wait to have read.
	select {
	case <-begun:
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := first.ExecContext(ctx, `UPDATE "counter" SET "n" = ? WHERE "id" = 1`, n+1); err != nil {
		t.Fatal(err)
	}
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatalf("a second write transaction failed rather than waiting its turn: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT "n" FROM "counter" WHERE "id" = 1`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("the counter reached %d after two increments", n)
	}
}

func TestValidateAnswersQuickly(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		start := time.Now()
		if err := db.Validate(t.Context()); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("validate took %v", elapsed)
		}
	})
}

func TestValidateFailsQuicklyAgainstSomethingUnreachable(t *testing.T) {
	// A dead address, so the check has to give up on its own deadline rather
	// than waiting for the operating system to.
	target, err := database.ParseURL("postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	start := time.Now()
	db, err := database.Open(ctx, target)
	if err == nil {
		_ = db.Close()
		t.Fatal("connected to an address with nothing on it")
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("gave up after %v, which is too slow to be useful", elapsed)
	}
}

func TestAnUpdateReportsRowsMatchedNotRowsChanged(t *testing.T) {
	// Several writes elsewhere are conditional — set this, but only if the row
	// is still the one that was read — and they read the affected count back
	// to find out whether the condition held. That only works if the count
	// means "matched" on every engine.
	//
	// Two of the four report "changed" unless asked otherwise, so an update
	// whose condition held but whose value was already correct reports zero
	// and the caller announces a conflict that never happened. It surfaced as
	// an approval failing with "the reasoning changed while this was being
	// agreed to" on exactly those two engines, for a decision nobody had
	// touched.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		scratchTable(t, db, "matched_rows", `"id" INTEGER PRIMARY KEY, "note" VARCHAR(16)`)
		if _, err := db.NewRaw(`INSERT INTO "matched_rows" ("id", "note") VALUES (1, 'same')`).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// The row exists and the condition holds. Nothing about it changes.
		result, err := db.NewRaw(`UPDATE "matched_rows" SET "note" = 'same' WHERE "id" = 1`).Exec(ctx)
		if err != nil {
			t.Fatal(err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			t.Fatal(err)
		}
		if affected != 1 {
			t.Errorf("an update that matched a row reported %d affected; "+
				"every conditional write reads this to mean the row was found", affected)
		}
	})
}
