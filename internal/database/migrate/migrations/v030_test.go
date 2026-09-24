// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// A database the v0.2.0 release built, holding a row in every table, is
// upgraded into exactly the schema a fresh install makes, and every value it
// held is still there. Rolled back, it is v0.2.0's schema again, still holding
// them, and upgraded a second time it is the fresh install's.
func TestAV020DatabaseUpgradesToTheFreshSchemaKeepingItsRows(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		// Held to v0.3.0 as it will be tagged. What a later migration changes
		// is that migration's test.
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)
		fresh := describe(t, ctx, db)
		if len(fresh) == 0 {
			t.Fatal("the fresh schema described as nothing, so nothing is compared")
		}

		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v020)
		built := describe(t, ctx, db)
		taggedSchema(t, "v0.2.0", db.Server.Engine, built)
		seedEvery(t, ctx, db)
		before := snapshot(t, ctx, db)

		dbtest.MigrateTo(t, db, v030)
		if diff := setDiff(fresh, describe(t, ctx, db)); diff != "" {
			t.Errorf("the upgraded schema differs from a fresh install's:\n%s", diff)
		}
		survived(t, ctx, db, before, nil, nil)
		addedByV030(t, ctx, db)
		if version, err := schema.Version(ctx, db); err != nil || version != v030 {
			t.Errorf("the upgrade left version %d (%v), want %d", version, err, v030)
		}
		// A second run finds nothing to do.
		dbtest.MigrateTo(t, db, v030)

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		if diff := setDiff(built, describe(t, ctx, db)); diff != "" {
			t.Errorf("rolled back, the schema differs from v0.2.0's:\n%s", diff)
		}
		survived(t, ctx, db, before, nil, nil)
		dbtest.MigrateTo(t, db, v030)
		if diff := setDiff(fresh, describe(t, ctx, db)); diff != "" {
			t.Errorf("upgraded a second time, the schema differs from a fresh install's:\n%s", diff)
		}
		leaveAtLatest(t, ctx, db)
	})
}

// A database the v0.1.0 release built is carried through every release's
// upgrade into exactly the schema a fresh install makes, keeping its rows.
func TestAV010DatabaseUpgradesThroughEveryReleaseKeepingItsRows(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)
		fresh := describe(t, ctx, db)

		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v010)
		taggedSchema(t, "v0.1.0", db.Server.Engine, describe(t, ctx, db))
		seed(t, ctx, db)
		before := snapshot(t, ctx, db)

		dbtest.MigrateTo(t, db, v030)
		if diff := setDiff(fresh, describe(t, ctx, db)); diff != "" {
			t.Errorf("upgraded from v0.1.0, the schema differs from a fresh install's:\n%s", diff)
		}
		survived(t, ctx, db, before, replacedByV020, nil)
		moved(t, ctx, db)
		addedByV030(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}

// v0.3.0's declaration of each table it changes names the columns the chain
// of migrations gives that table.
func TestTheV030DeclarationsAreTheTablesTheMigrationsBuild(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)
		declared, err := migrations.DeclaredV030(db.Server.Engine)
		if err != nil {
			t.Fatal(err)
		}
		if len(declared) == 0 {
			t.Fatal("v0.3.0 declares no table, so nothing was compared")
		}
		built := columns(t, ctx, db)
		for table, names := range declared {
			var have []string
			for _, c := range built[table] {
				have = append(have, c.name)
			}
			want := slices.Clone(names)
			slices.Sort(want)
			slices.Sort(have)
			if !slices.Equal(want, have) {
				t.Errorf("%s is declared with %v and the migrations build %v", table, want, have)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

// addedByV030 checks what the upgrade wrote into the columns v0.2.0 did not
// have: a recorded flaw rated in force is stamped with its first recording,
// every report came from outside, and no component has a license until a scan
// states one.
func addedByV030(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	rows := read(t, ctx, db, "finding", []string{"id", "kind", "opened_at", "rated_at"})
	entered := 0
	for _, row := range rows {
		if row["kind"] != "entered" {
			if row["rated_at"] != "NULL" {
				t.Errorf("scanned finding %s was stamped rated at %s", row["id"], row["rated_at"])
			}
			continue
		}
		entered++
		if row["rated_at"] != row["opened_at"] {
			t.Errorf("recorded flaw %s was stamped rated at %s, and first recorded at %s",
				row["id"], row["rated_at"], row["opened_at"])
		}
	}
	if entered == 0 {
		t.Error("no recorded flaw came across, so the stamp was not checked")
	}
	for _, check := range []struct{ table, column, want string }{
		{"flaw_report", "found_here", "false"},
		{"component", "license", "null"},
	} {
		values := read(t, ctx, db, check.table, []string{check.column})
		if len(values) == 0 {
			t.Errorf("%s held no rows, so %s was not checked", check.table, check.column)
		}
		for _, row := range values {
			// MySQL and MariaDB hold a boolean as a number.
			if got := strings.ToLower(row[check.column]); got != check.want && (check.want != "false" || got != "0") {
				t.Errorf("%s.%s came across as %s, want %s", check.table, check.column, got, check.want)
			}
		}
	}
}
