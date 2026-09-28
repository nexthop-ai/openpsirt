// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Upgraded, every trail row v0.4.0 wrote is a person's and keeps its person,
// and configuration may then record a change with no person behind it.
// Rolled back, a row configuration wrote goes, because v0.4.0 has no place
// for a change nobody made, and the table is the one v0.4.0 built.
func TestAnUpgradeKeepsEveryTrailRowAPersons(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)
		built := linesOf(describe(t, ctx, db), "admin_change", "")
		if len(built) == 0 {
			t.Fatal("the v0.4.0 trail described as nothing, so nothing is compared")
		}

		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin", "", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "admin_change" ("at", "by", "kind", "about", "became")`+
			` VALUES (?, ?, ?, ?, ?)`, time.Now().UTC(), admin.ID, "setting", "triage-floor", "high").
			Exec(ctx); err != nil {
			t.Fatal(err)
		}

		dbtest.MigrateTo(t, db, v050)
		var rows []struct {
			Actor string `bun:"actor"`
			By    *int64 `bun:"by"`
		}
		if err := db.DB.NewRaw(`SELECT "actor", "by" FROM "admin_change"`).Scan(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Actor != "person" || rows[0].By == nil || *rows[0].By != admin.ID {
			t.Errorf("upgraded, the trail reads %+v", rows)
		}
		if err := trail.NewStore(db.DB).RecordByConfiguration(ctx, trail.Account, "operator",
			nil, trail.Said(trail.NamedInConfiguration, true)); err != nil {
			t.Fatalf("upgraded, configuration could not record a change: %v", err)
		}

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		var left []int64
		if err := db.DB.NewRaw(`SELECT "by" FROM "admin_change"`).Scan(ctx, &left); err != nil {
			t.Fatal(err)
		}
		if len(left) != 1 || left[0] != admin.ID {
			t.Errorf("rolled back, the trail holds rows by %v, want the person's alone", left)
		}
		back := linesOf(describe(t, ctx, db), "admin_change", "")
		for _, line := range built {
			if !slices.Contains(back, line) {
				t.Errorf("rolled back, the trail lacks %q", line)
			}
		}
		for _, line := range back {
			if !slices.Contains(built, line) {
				t.Errorf("rolled back, the trail has %q, which v0.4.0 did not build", line)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

// v0.5.0's declaration of each table it changes is the table the chain of
// migrations builds, on every engine. SQLite builds it from the declaration and
// the servers alter the table v0.4.0 built, so nothing else holds the two to
// each other. Each is built beside the real table under a scratch name and the
// two are described alike.
func TestTheV050DeclarationsAreTheTablesTheMigrationsBuild(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v050)
		declared := migrations.StatementsV050(db.Server.Engine)
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
				if !slices.Contains(fromDeclaration, line) {
					t.Errorf("the migrations build %q on %s and v0.5.0 does not declare it", line, table)
				}
			}
		}
		if compared == 0 || compared != len(declared) {
			t.Errorf("compared %d of the %d tables v0.5.0 declares", compared, len(declared))
		}
		for _, table := range made {
			if _, err := db.ExecContext(ctx, `DROP TABLE "`+table+`"`); err != nil {
				t.Fatalf("drop %s: %v", table, err)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}
