// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
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
		unrecordLatest(t, db)
		dbtest.MigrateTo(t, db, v0140)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0140(db.Server.Engine))
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

// A start that stopped after the correction table was made and before its
// index, which MySQL and MariaDB keep since they commit each schema
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
		drops := []string{`DROP INDEX "source_correction_product_idx"`}
		if db.Server.Engine == database.MySQL || db.Server.Engine == database.MariaDB {
			drops = []string{
				`ALTER TABLE "source_correction" DROP FOREIGN KEY "source_correction_product_fk"`,
				`DROP INDEX "source_correction_product_idx" ON "source_correction"`,
				`ALTER TABLE "source_correction" ADD CONSTRAINT "source_correction_product_fk" ` +
					`FOREIGN KEY ("product_id") REFERENCES "product"("id")`,
			}
		}
		for _, drop := range drops {
			if _, err := db.ExecContext(ctx, drop); err != nil {
				t.Fatal(err)
			}
		}
		unrecordLatest(t, db)
		dbtest.MigrateTo(t, db, v0140)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0140(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}
