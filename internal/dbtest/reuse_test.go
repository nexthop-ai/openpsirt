// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// The harness has two paths and only one of them had ever run.
//
// A server database is created and migrated on first use, and kept between
// runs because applying the migrations is nearly the whole cost of a server
// engine. An ordinary run takes the create-and-migrate path, so nothing in the
// suite otherwise reaches the other one: recognizing a database that is
// already there, emptying it instead of migrating it, or dropping what an
// edited migration left behind. The DROP in particular is quoted the standard
// way, which the MySQL connections accept, and only running it says so.
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

// Clearing a kept database empties it and leaves the schema alone. The
// distinction matters: the first test in a package must see an empty database
// whether or not somebody ran it before, and it must not have to migrate one.
func TestClearingAKeptDatabaseEmptiesItAndLeavesTheSchema(t *testing.T) {
	forEachServer(t, func(t *testing.T, engine database.Engine, base string) {
		ctx := t.Context()

		// This package's own database, already made and migrated by the
		// harness. Building a second one would apply every migration again,
		// which is the cost reuse exists to avoid.
		own, err := serverDatabase(engine, base)
		if err != nil {
			t.Fatalf("prepare a %s database: %v", engine, err)
		}
		db := Open(t, own)

		before, err := schema.Version(ctx, db)
		if err != nil {
			t.Fatalf("read the schema version: %v", err)
		}
		if before == 0 {
			t.Fatal("the database reports schema version 0, so it was never migrated")
		}

		if _, err := db.ExecContext(ctx,
			`INSERT INTO "application_setting" ("name", "value", "updated_at") VALUES (?, ?, ?)`,
			"dbtest.reuse", "left behind by an earlier run", time.Now().UTC()); err != nil {
			t.Fatalf("write a row for the clear to find: %v", err)
		}

		if err := clearFresh(own); err != nil {
			t.Fatalf("clear %s: %v", engine, err)
		}

		var rows int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM "application_setting"`).Scan(&rows); err != nil {
			t.Fatalf("count what survived: %v", err)
		}
		if rows != 0 {
			t.Errorf("%d row(s) survived the clear, so a kept database hands "+
				"the next run the last one's rows", rows)
		}

		after, err := schema.Version(ctx, db)
		if err != nil {
			t.Fatalf("read the schema version back: %v", err)
		}
		if after != before {
			t.Errorf("the schema version moved from %d to %d, so clearing "+
				"took the schema with it", before, after)
		}
	})
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
		t.Fatalf("parse %q: %v", base, err)
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
