// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/uptrace/bun"
)

// A server database is created and migrated on first use, and kept between
// runs because applying the migrations is nearly the whole cost of a server
// engine. An ordinary run takes one of the harness's paths, so nothing else in
// the suite reaches the others: recognizing a database that is already there,
// building again one an interrupted run left half migrated, and dropping what
// an edited migration left behind. The DROP in particular is quoted the
// standard way, which the MySQL connections accept, and only running it says
// so.
//
// These run against the servers only. SQLite has no reuse path: each test
// takes a copy of a migrated template file.

// The first call makes the database, the second recognizes it, and a third
// under the same prefix with a different schema fingerprint drops the one the
// older migrations built.
func TestAKeptDatabaseIsRecognizedAndAnOlderSchemaDropped(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		ctx := t.Context()
		admin := openAdmin(t, base)

		// Two names under one prefix, differing only where the fingerprint of
		// the migrations sits — which is exactly what an edited migration
		// produces.
		prefix := fmt.Sprintf("openpsirt_t_reuse_%s_", suffixFor(t, engine))
		first, second := prefix+"aaaaaa", prefix+"bbbbbb"
		t.Cleanup(func() {
			for _, name := range []string{first, second} {
				if _, err := admin.ExecContext(context.WithoutCancel(ctx),
					`DROP DATABASE IF EXISTS "`+name+`"`); err != nil {
					t.Errorf("clean up %s: %v", name, err)
				}
			}
		})

		kept, err := ensureDatabase(ctx, admin, engine, first)
		if err != nil {
			t.Fatalf("make %s: %v", first, err)
		}
		if kept {
			t.Fatalf("%s did not exist and was reported as kept", first)
		}

		kept, err = ensureDatabase(ctx, admin, engine, first)
		if err != nil {
			t.Fatalf("recognize %s: %v", first, err)
		}
		if !kept {
			t.Errorf("%s exists and was reported as new, so the harness would "+
				"migrate it again rather than empty it", first)
		}

		// The same package, a moved schema. The older database is what an
		// edited migration leaves behind, and leaving it would accumulate one
		// per edit on every developer's server.
		kept, err = ensureDatabase(ctx, admin, engine, second)
		if err != nil {
			t.Fatalf("make %s: %v", second, err)
		}
		if kept {
			t.Errorf("%s did not exist and was reported as kept", second)
		}
		left, err := databasesFor(ctx, admin, engine, prefix)
		if err != nil {
			t.Fatalf("list the databases under %s: %v", prefix, err)
		}
		if len(left) != 1 || left[0] != second {
			t.Errorf("under %s the server holds %v, wanted %s alone — the "+
				"database an older schema built was not dropped", prefix, left, second)
		}
	})
}

// A run killed while it migrated leaves the package's database holding part
// of the schema. The next run builds it again, where using it as it stands
// fails every test in the package until somebody drops it by hand.
//
// Verified by making whole answer true for any database: the half-built one is
// then handed back at the version it stopped at. And by skipping the drop: the
// database is then migrated forward and keeps the table no migration made.
func TestAHalfBuiltDatabaseIsBuiltAgain(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		ctx := t.Context()
		admin := openAdmin(t, base)
		name := fmt.Sprintf("openpsirt_t_halfbuilt_%s_aaaaaa", suffixFor(t, engine))
		t.Cleanup(func() {
			if _, err := admin.ExecContext(context.WithoutCancel(ctx),
				`DROP DATABASE IF EXISTS "`+name+`"`); err != nil {
				t.Errorf("clean up %s: %v", name, err)
			}
		})

		// The database an interrupted run leaves: made, and migrated no
		// further than the first migration.
		if _, err := ensureDatabase(ctx, admin, engine, name); err != nil {
			t.Fatalf("make %s: %v", name, err)
		}
		own, err := databaseURL(base, engine, name)
		if err != nil {
			t.Fatal(err)
		}
		half := openClosed(t, own)
		if err := migrate.UpTo(ctx, half, slog.New(slog.NewTextHandler(io.Discard, nil)), 1); err != nil {
			t.Fatalf("apply the first migration: %v", err)
		}
		// What an interrupted schema statement leaves on MySQL and MariaDB:
		// something no recorded version accounts for. Migrating forward
		// keeps it; only the drop removes it.
		if _, err := half.ExecContext(ctx, `CREATE TABLE "dbtest_leftover" ("id" INT)`); err != nil {
			t.Fatalf("leave a table no migration made: %v", err)
		}
		if err := half.Close(); err != nil {
			t.Fatal(err)
		}

		got, err := prepareServer(ctx, engine, base, name)
		if err != nil {
			t.Fatalf("prepare the half-built database: %v", err)
		}
		db := Open(t, got)
		applied, err := schema.Version(ctx, db)
		if err != nil {
			t.Fatalf("read the schema version: %v", err)
		}
		expected, err := schema.Expected()
		if err != nil {
			t.Fatal(err)
		}
		if applied != expected {
			t.Errorf("the database was handed back at version %d, want %d", applied, expected)
		}
		var leftover int
		if err := db.NewSelect().TableExpr(`"dbtest_leftover"`).ColumnExpr("COUNT(*)").
			Scan(ctx, &leftover); err == nil {
			t.Errorf("a table no migration made survived: the database was migrated " +
				"forward rather than built again")
		}
		// The first test's clear reads every declared table, so a schema
		// missing one fails here rather than in the package's tests.
		if err := clear(ctx, db); err != nil {
			t.Errorf("empty the rebuilt database: %v", err)
		}
	})
}

// openClosed opens the database at url for a test that closes it itself.
func openClosed(t *testing.T, url string) *database.DB {
	t.Helper()
	target, err := database.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.Open(t.Context(), target)
	if err != nil {
		t.Fatalf("open %s: %v", target.Redacted, err)
	}
	return db
}

// forEachServer runs fn against every configured server engine, as a subtest.
// SQLite is left out because it has no reuse path.
func forEachServer(t *testing.T, fn func(t *testing.T, engine database.Engine, base string)) {
	t.Helper()
	for _, engine := range database.Engines() {
		if engine == database.SQLite {
			continue
		}
		t.Run(string(engine), func(t *testing.T) {
			engines.SkipUnless(t, engine)
			base := os.Getenv(urlEnv[engine])
			if base == "" {
				t.Skipf("%s is not set, so %s is untested here", urlEnv[engine], engine)
			}
			fn(t, engine, base)
		})
	}
}

// openAdmin connects to the server itself rather than to a database on it,
// which is the connection the create and drop statements are issued over.
func openAdmin(t *testing.T, base string) *database.DB {
	t.Helper()
	target, err := database.ParseURL(base)
	if err != nil {
		t.Fatalf("parse the database URL: %v", err)
	}
	admin, err := database.Open(context.Background(), target)
	if err != nil {
		t.Fatalf("open %s: %v", target.Redacted, err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Errorf("close %s: %v", target.Engine, err)
		}
	})
	return admin
}

// suffixFor keeps two engines' subtests from naming the same database, since
// they may be the same server.
func suffixFor(t *testing.T, engine database.Engine) string {
	t.Helper()
	return string(engine)[:3]
}

// hookCount is a query hook that counts the statements it sees.
type hookCount struct{ n atomic.Int64 }

func (h *hookCount) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	h.n.Add(1)
	return ctx
}
func (h *hookCount) AfterQuery(context.Context, *bun.QueryEvent) {}

// Every test in a binary shares one pool on a server, and a test may add a
// query hook to the handle it was given. The hook belongs to that test alone:
// a later test's statements reaching it would run the earlier test's code in
// the later test, concurrently with whatever the later test does.
func TestAQueryHookStaysWithTheTestThatAddedIt(t *testing.T) {
	Servers(t, func(t *testing.T, db *database.DB) {
		ctx := context.Background()
		serverMu.Lock()
		own := serverURLs[db.Server.Engine]
		serverMu.Unlock()
		later, err := serverConnection(db.Server.Engine, own)
		if err != nil {
			t.Fatal(err)
		}

		hook := &hookCount{}
		db.AddQueryHook(hook)
		if _, err := later.NewSelect().ColumnExpr("1").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if n := hook.n.Load(); n != 0 {
			t.Errorf("a hook one test added saw %d statements another test made", n)
		}
		if _, err := db.NewSelect().ColumnExpr("1").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if n := hook.n.Load(); n != 1 {
			t.Errorf("the hook saw %d of its own test's statements, want 1", n)
		}
	})
}
