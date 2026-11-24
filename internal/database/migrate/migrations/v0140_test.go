// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// v0140 is the migration v0.14.0 carries v0.13.0's schema across with.
const v0140 = 48

// The v0.14.0 upgrade builds what v0.14.0 declares, over a database v0.13.0
// built and over one it has already run on, as a start that stopped after
// the index was made leaves it.
func TestTheV0140UpgradeBuildsItsDeclarations(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0130)
		dbtest.MigrateTo(t, db, v0140)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0140(db.Server.Engine))
		unrecordAt(t, db, v0140)
		dbtest.MigrateTo(t, db, v0140)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0140(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// A start of the v0.14.0 upgrade that fails part way leaves the schema, the
// record of the version applied included, as v0.13.0 built it on PostgreSQL
// and SQLite, which run the whole upgrade in one transaction. The failure is
// at its last step, after every other has run: a component's name is kept in
// a table of that name already standing without the columns the step writes.
// What the migration runner makes before any migration, its lease, is there
// before and after.
func TestAStoppedV0140StartLeavesTheV0130Schema(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if db.Server.Engine == database.MySQL || db.Server.Engine == database.MariaDB {
			t.Skipf("%s commits each schema statement as it runs", db.Server.Engine)
		}
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0130)
		s := &seederV0130{t: t, db: db, at: time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)}
		s.component("openssl", "3.0.11", "pkg:deb/debian/openssl@3.0.11")
		before := describe(t, ctx, db)
		if _, err := db.ExecContext(ctx, `CREATE TABLE "component_name" ("in_the_way" INTEGER)`); err != nil {
			t.Fatal(err)
		}
		if err := migrate.UpTo(ctx, db, quiet(), v0140, 0); err == nil {
			t.Fatal("the upgrade ran past a table in the way of its last step")
		}
		if _, err := db.ExecContext(ctx, `DROP TABLE "component_name"`); err != nil {
			t.Fatal(err)
		}
		var version int64
		if err := db.DB.NewRaw(`SELECT MAX("version_id") FROM "`+migrate.VersionTable+`" WHERE "is_applied" = ?`,
			true).Scan(ctx, &version); err != nil {
			t.Fatal(err)
		}
		if version != v0130 {
			t.Errorf("the stopped start left the version at %d, want %d", version, v0130)
		}
		if diff := setDiff(before, describe(t, ctx, db)); diff != "" {
			t.Errorf("the stopped start left the schema changed from v0.13.0's:\n%s", diff)
		}
		leaveAtLatest(t, ctx, db)
	})
}

// A start of the v0.14.0 upgrade that stopped after a build's own claims took
// their status notes column, as MySQL and MariaDB leave one, finishes into
// what v0.14.0 declares.
func TestTheV0140UpgradeFinishesAStartThatStoppedAfterTheClaimNotes(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0130)
		if err := migrations.StopV0140AfterClaimNotes(ctx, db); err != nil {
			t.Fatal(err)
		}
		dbtest.MigrateTo(t, db, v0140)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0140(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// A start that stopped after the correction table or the component name table
// was made and before its index, which MySQL and MariaDB keep since they commit each schema
// statement, is finished by the next start.
func TestTheV0140UpgradeMakesAnIndexAStoppedStartLeftUnmade(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0130)
		dbtest.MigrateTo(t, db, v0140)
		// MySQL and MariaDB keep an index under every foreign key: a table
		// made with no index of its own holds one named after the key, which
		// a later index able to serve the key replaces.
		drops := []string{`DROP INDEX "source_correction_product_idx"`, `DROP INDEX "component_name_component_idx"`}
		if db.Server.Engine == database.MySQL || db.Server.Engine == database.MariaDB {
			drops = []string{
				`ALTER TABLE "source_correction" DROP FOREIGN KEY "source_correction_product_fk"`,
				`DROP INDEX "source_correction_product_idx" ON "source_correction"`,
				`ALTER TABLE "source_correction" ADD CONSTRAINT "source_correction_product_fk" ` +
					`FOREIGN KEY ("product_id") REFERENCES "product"("id")`,
				`ALTER TABLE "component_name" DROP FOREIGN KEY "component_name_component_fk"`,
				`DROP INDEX "component_name_component_idx" ON "component_name"`,
				`ALTER TABLE "component_name" ADD CONSTRAINT "component_name_component_fk" ` +
					`FOREIGN KEY ("component_id") REFERENCES "component"("id")`,
			}
		}
		for _, drop := range drops {
			if _, err := db.ExecContext(ctx, drop); err != nil {
				t.Fatal(err)
			}
		}
		unrecordAt(t, db, v0140)
		dbtest.MigrateTo(t, db, v0140)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0140(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// The v0.14.0 upgrade keeps every name each component goes by: its own name
// folded, and the name its package identifier gives, folded and decoded,
// where that differs; and nothing for a component with neither. A start after
// one that stopped keeps what it found and adds what it left.
func TestTheV0140UpgradeKeepsEveryNameAComponentGoesBy(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0130)
		s := &seederV0130{t: t, db: db, at: time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)}
		renamed := s.component("Repro Platform", "05.47.45.0027",
			"pkg:generic/repro/InsydeH2O@05.47.45.0027?arch=x86_64#bin")
		scoped := s.component("core", "7.0.0", "pkg:npm/%40babel/core%2Bx@7.0.0")
		bare := s.component("bash", "5.2", "")
		same := s.component("OpenSSL", "3.0.11", "pkg:deb/debian/openssl@3.0.11")
		other := s.component("thing", "1", "https://example.com/thing")
		want := map[int64][]string{renamed: {"insydeh2o", "repro platform"}, scoped: {"core", "core+x"},
			bare: {"bash"}, same: {"openssl"}, other: {"thing"}}
		held := func() {
			t.Helper()
			for id, names := range want {
				var got []string
				if err := db.DB.NewRaw(`SELECT "name_folded" FROM "component_name" WHERE "component_id" = ? ORDER BY "name_folded"`, id).
					Scan(ctx, &got); err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(got, names) {
					t.Errorf("component %d goes by %q, want %q", id, got, names)
				}
			}
		}
		dbtest.MigrateTo(t, db, v0140)
		held()
		countedAsWritten(t, db)
		if _, err := db.ExecContext(ctx, `DELETE FROM "component_name" WHERE "component_id" IN (?)`,
			bun.List([]int64{renamed, scoped})); err != nil {
			t.Fatal(err)
		}
		unrecordAt(t, db, v0140)
		dbtest.MigrateTo(t, db, v0140)
		held()
		leaveAtLatest(t, ctx, db)
	})
}

// countedAsWritten fails unless the names a rehearsal works out from the
// components match the rows the upgrade wrote, since a rehearsal holds the
// upgrade's fill to that count.
func countedAsWritten(t *testing.T, db *database.DB) {
	t.Helper()
	var components []struct {
		Purl   string `bun:"purl"`
		Folded string `bun:"name_folded"`
	}
	if err := db.DB.NewRaw(`SELECT COALESCE("purl", '') AS "purl", COALESCE("name_folded", '') AS "name_folded" FROM "component"`).
		Scan(t.Context(), &components); err != nil {
		t.Fatal(err)
	}
	var counted, written int64
	for _, c := range components {
		counted += migrations.NamesV0140(c.Purl, c.Folded)
	}
	if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "component_name"`).Scan(t.Context(), &written); err != nil {
		t.Fatal(err)
	}
	if counted != written {
		t.Errorf("a rehearsal counts %d names for the components, and the upgrade wrote %d", counted, written)
	}
}

// The upgrade carries its own copy of the rule naming a component's package,
// so a later change to the application's leaves what the upgrade wrote as it
// was. Held to the application's here, over every shape the rule reads.
func TestTheV0140UpgradeNamesAPackageAsTheApplicationDoes(t *testing.T) {
	purls := []string{"", "pkg:deb/debian/openssl@3.0.11-1?arch=amd64", "PKG:Generic/Repro/InsydeH2O@1#bin",
		"pkg:npm/%40babel/core%2Bx@7.0.0", "pkg:npm/@babel/core", "pkg:generic/foo%zz\x01@1",
		"pkg:generic/f%01oo@1", "pkg:generic/x", "pkg:generic", "pkg:/generic/x@1", "pkg://deb/debian/x@1",
		"https://example.com/thing", "not a purl", " pkg:pypi/Requests@2 ", "pkg:golang/golang.org/x/net@v0.7.0",
		"pkg:generic/" + strings.Repeat("Ü", 300) + "@1", "pkg:generic/ünï@1", "pkg:maven/a/b@1?type=jar"}
	for _, purl := range purls {
		if got, want := migrations.PackageFoldedV0140(purl), graph.PackageFolded(purl); got != want {
			t.Errorf("%q: the upgrade names %q, the application %q", purl, got, want)
		}
	}
	if len(purls) == 0 {
		t.Fatal("no identifier was compared, so this checked nothing")
	}
}
