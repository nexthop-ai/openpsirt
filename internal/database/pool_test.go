package database_test

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"

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
		got := db.Stats().MaxOpenConnections
		want := database.DefaultPool().MaxOpen
		if db.Server.Engine == database.SQLite {
			// One writer, so more connections add contention rather than
			// concurrency.
			want = 1
		}
		if got != want {
			t.Errorf("%s: max open connections is %d, want %d", db.Server.Engine, got, want)
		}
	})
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
		if _, err := db.NewRaw(`CREATE TABLE "matched_rows" ("id" INTEGER PRIMARY KEY, "note" VARCHAR(16))`).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.NewRaw(`DROP TABLE "matched_rows"`).Exec(context.WithoutCancel(ctx))
		})
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
