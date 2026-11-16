// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// partV0130 is one thing the v0.13.0 upgrade changes: the rows a v0.12.0
// database holds for it, the check those rows are held to once the upgrade
// ends, and the points a start of the upgrade can stop at before it.
type partV0130 struct {
	// name is the check's, and its subtest's.
	name string
	// seed writes the part's rows into a v0.12.0 database and answers the
	// check, or nil where the declarations are the whole check.
	seed func(t *testing.T, db *database.DB) func(t *testing.T)
	// stops are in the order the upgrade reaches them.
	stops []stopV0130
}

// stopV0130 makes, by hand, what a start of the v0.13.0 upgrade that stopped
// at one point left.
type stopV0130 struct {
	name string
	make func(t *testing.T, db *database.DB) error
}

// partsV0130 is every part, in the order the upgrade changes them. Each part
// reads and writes rows of its own, found by their identifiers or by the
// product, build or advisory its seed made, never a whole table.
func partsV0130() []partV0130 {
	parts := append([]partV0130{
		coversPartV0130(),
		marksPartV0130(),
		nodePartV0130(),
		statementPartV0130(),
		statementSubjectsPartV0130(),
		withdrawerPartV0130(),
		packageIdentifiersPartV0130(),
		publishedDocumentsPartV0130(),
		advisoryUnchangedPartV0130(),
		stoppedCredentialPartV0130(),
		remotesPartV0130(),
		storedIdentifyingPartV0130(),
		keysPartV0130(),
	}, splitPartsV0130()...)
	parts = append(parts, ownProductPartsV0130()...)
	return append(parts, fixStatePartV0130())
}

// A v0.12.0 database holding every part's rows upgrades to v0.13.0's
// declarations, and each part holds to its check. Then, on MySQL and MariaDB,
// a database per stop number is stopped at each part's stop of that number,
// in the order the upgrade reaches them, upgraded once, and each part with a
// stop there is held to its check.
//
// The parts change tables of their own, so the stops of different parts are
// independent, and a database takes one of each as the v0.11.0 and v0.12.0
// resume tests do; building a database to v0.12.0 is most of what such a test
// costs. PostgreSQL and SQLite run the upgrade in one transaction, so a start
// that stopped leaves the schema as v0.12.0 built it (
// TestAStoppedV0130StartLeavesTheV0120Schema), and neither makes these stops.
func TestAV0120DatabaseUpgradesToV0130(t *testing.T) {
	parts := partsV0130()
	most := 0
	for _, p := range parts {
		most = max(most, len(p.stops))
	}
	upgrade := func(t *testing.T, db *database.DB, stop int) {
		t.Helper()
		ctx := t.Context()
		if stop > 0 && (db.Server.Engine == database.SQLite || db.Server.Engine == database.Postgres) {
			t.Skipf("%s changes the schema in one transaction, so it never stops there", db.Server.Engine)
		}
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
		type held struct {
			name  string
			check func(t *testing.T)
		}
		var checks []held
		for i, p := range parts {
			if stop > len(p.stops) {
				continue
			}
			if p.seed != nil {
				before := highestV0120(t, db)
				check := p.seed(t, db)
				setApartV0120(t, db, before, i)
				if check != nil {
					checks = append(checks, held{p.name, check})
				}
			}
			if stop > 0 {
				if err := p.stops[stop-1].make(t, db); err != nil {
					t.Fatalf("make what a start stopped %s left: %v", p.stops[stop-1].name, err)
				}
			}
		}
		dbtest.MigrateTo(t, db, v0130)
		t.Run("TheV0130DeclarationsAreBuilt", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV0130(db.Server.Engine))
		})
		for _, c := range checks {
			t.Run(c.name, c.check)
		}
		leaveAtLatest(t, ctx, db)
	}
	t.Run("whole", func(t *testing.T) {
		dbtest.Each(t, func(t *testing.T, db *database.DB) { upgrade(t, db, 0) })
	})
	for stop := 1; stop <= most; stop++ {
		var named string
		for _, p := range parts {
			if stop <= len(p.stops) {
				named += fmt.Sprintf("; %s %s", p.name, p.stops[stop-1].name)
			}
		}
		t.Run(fmt.Sprintf("stopped %d", stop), func(t *testing.T) {
			t.Log("stopped" + named[1:])
			dbtest.Each(t, func(t *testing.T, db *database.DB) { upgrade(t, db, stop) })
		})
	}
}

// apartV0120 is each column a part's seed writes that another part's seed may
// write the same value to, and that has to be unique. The v0.13.0 upgrade
// reads none of them.
var apartV0120 = []struct {
	table   string
	columns []string
}{
	{"product", []string{"name"}},
	{"person", []string{"identity"}},
	{"advisory", []string{"identifier", "identifier_folded"}},
	{"vulnerability", []string{"identifier", "identifier_folded"}},
	{"component", []string{"identity"}},
}

// highestV0120 is the highest identifier each table in apartV0120 holds.
func highestV0120(t *testing.T, db *database.DB) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, a := range apartV0120 {
		var n int64
		if err := db.DB.NewRaw(`SELECT COALESCE(MAX("id"), 0) FROM "`+a.table+`"`).
			Scan(t.Context(), &n); err != nil {
			t.Fatal(err)
		}
		out[a.table] = n
	}
	return out
}

// setApartV0120 gives the rows a part's seed wrote past before a value no
// other part's seed writes, by the part's place in the list: each unique
// column takes the place as a suffix, and an advisory's number is moved past
// every other part's.
func setApartV0120(t *testing.T, db *database.DB, before map[string]int64, place int) {
	t.Helper()
	ctx := t.Context()
	suffix := fmt.Sprintf("-part-%d", place)
	for _, a := range apartV0120 {
		var ids []int64
		if err := db.DB.NewRaw(`SELECT "id" FROM "`+a.table+`" WHERE "id" > ? ORDER BY "id"`, before[a.table]).
			Scan(ctx, &ids); err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			for _, column := range a.columns {
				var value string
				if err := db.DB.NewRaw(`SELECT "`+column+`" FROM "`+a.table+`" WHERE "id" = ?`, id).
					Scan(ctx, &value); err != nil {
					t.Fatal(err)
				}
				if _, err := db.DB.NewRaw(`UPDATE "`+a.table+`" SET "`+column+`" = ? WHERE "id" = ?`,
					value+suffix, id).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if a.table == "advisory" {
				if _, err := db.DB.NewRaw(`UPDATE "advisory" SET "mint_number" = "mint_number" + ? WHERE "id" = ?`,
					1000*(place+1), id).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}

// A start of the v0.13.0 upgrade that fails part way leaves the schema, the
// record of the version applied included, as v0.12.0 built it on PostgreSQL
// and SQLite, which run the whole upgrade in one transaction. The failure is
// at its last step, after every other has run: the record of schema changes
// is made where a table of that name already stands. What the migration
// runner makes before any migration, its lease, is there before and after.
func TestAStoppedV0130StartLeavesTheV0120Schema(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if db.Server.Engine == database.MySQL || db.Server.Engine == database.MariaDB {
			t.Skipf("%s commits each schema statement as it runs", db.Server.Engine)
		}
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
		before := describe(t, ctx, db)
		if _, err := db.ExecContext(ctx, `CREATE TABLE "schema_change" ("in_the_way" INTEGER)`); err != nil {
			t.Fatal(err)
		}
		if err := migrate.UpTo(ctx, db, quiet(), v0130, 0); err == nil {
			t.Fatal("the upgrade ran past a table in the way of its last step")
		}
		if _, err := db.ExecContext(ctx, `DROP TABLE "schema_change"`); err != nil {
			t.Fatal(err)
		}
		var version int64
		if err := db.DB.NewRaw(`SELECT MAX("version_id") FROM "`+migrate.VersionTable+`" WHERE "is_applied" = ?`,
			true).Scan(ctx, &version); err != nil {
			t.Fatal(err)
		}
		if version != v0120 {
			t.Errorf("the stopped start left the version at %d, want %d", version, v0120)
		}
		if diff := setDiff(before, describe(t, ctx, db)); diff != "" {
			t.Errorf("the stopped start left the schema changed from v0.12.0's:\n%s", diff)
		}
		leaveAtLatest(t, ctx, db)
	})
}
