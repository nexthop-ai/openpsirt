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
		survived(t, ctx, db, before, nil)
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
		survived(t, ctx, db, before, nil)
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
		survived(t, ctx, db, before, replacedByV020)
		moved(t, ctx, db)
		addedByV030(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}

// v0.3.0's declaration of each table it changes is the table the chain of
// migrations builds: every column with its type, nullability and default,
// every constraint and every index, on every engine. Migration 38 runs none of
// these statements — it adds three columns — so nothing else holds a
// declaration to the table it describes, and a freeze would record one that
// is wrong for good. Each is built beside the real table under a scratch name
// and the two are described alike.
func TestTheV030DeclarationsAreTheTablesTheMigrationsBuild(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)
		declared := migrations.StatementsV030(db.Server.Engine)
		var made []string
		for table, statements := range declared {
			for _, stmt := range statements {
				if _, err := db.ExecContext(ctx, scratch(table, stmt)); err != nil {
					t.Fatalf("build %s's declaration under a scratch name: %v\n%s", table, err, stmt)
				}
			}
			made = append(made, scratchPrefix+table)
		}
		described := describe(t, ctx, db)
		compared := 0
		for table := range declared {
			built := linesOf(described, table, "")
			fromDeclaration := linesOf(described, scratchPrefix+table, scratchPrefix)
			if len(built) == 0 || len(fromDeclaration) == 0 {
				t.Errorf("%s described as %d lines built and %d declared, so nothing was compared",
					table, len(built), len(fromDeclaration))
				continue
			}
			compared++
			for _, line := range fromDeclaration {
				if !slices.Contains(built, line) {
					t.Errorf("%s is declared with %q and the migrations do not build it", table, line)
				}
			}
			for _, line := range built {
				if !slices.Contains(fromDeclaration, line) && !madeElsewhere(table, line) {
					t.Errorf("the migrations build %q on %s and v0.3.0 does not declare it", line, table)
				}
			}
		}
		if compared != len(declared) || compared != 3 {
			t.Errorf("compared %d of the tables v0.3.0 declares, want 3", compared)
		}
		for _, table := range made {
			if _, err := db.ExecContext(ctx, `DROP TABLE "`+table+`"`); err != nil {
				t.Fatalf("drop %s: %v", table, err)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

// scratchPrefix names a declared table built beside the real one. Every name
// a declaration makes starts with its table's name, so prefixing those names
// keeps the index and constraint names of the two apart on engines where
// those are unique across a database.
const scratchPrefix = "zz_"

func scratch(table, stmt string) string {
	return strings.ReplaceAll(stmt, `"`+table, `"`+scratchPrefix+table)
}

// linesOf is the lines of a description about one table, with the scratch
// prefix taken out of each so the two read alike.
func linesOf(described []string, table, strip string) []string {
	var out []string
	for _, line := range described {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		about := fields[1]
		if fields[0] == "foreign" && len(fields) > 2 {
			about = fields[2]
		}
		about, _, _ = strings.Cut(about, ".")
		if about != table {
			continue
		}
		if strip != "" {
			line = strings.ReplaceAll(line, strip, "")
		}
		out = append(out, line)
	}
	return out
}

// madeElsewhere is what a table carries that another migration makes rather
// than the table's own declaration: an index added after the table was.
func madeElsewhere(table, line string) bool {
	for _, name := range map[string][]string{"finding": {"finding_component_idx"}}[table] {
		if strings.Contains(line, name) {
			return true
		}
	}
	return false
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
