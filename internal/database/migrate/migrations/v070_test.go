// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v070 is the migration v0.7.0 carries v0.6.0's schema across with.
const v070 = 41

// A v0.6.0 database is upgraded. Its findings and runs gain the record lines
// and the snapshot, holding none.
func TestAV060DatabaseUpgradesToV070(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v060)
		dbtest.MigrateTo(t, db, v070)

		var findings, runs int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "finding" WHERE "unaffected_by" IS NOT NULL`).
			Scan(ctx, &findings); err != nil {
			t.Fatalf("the finding table has no record lines: %v", err)
		}
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "scan_run" WHERE "records_version" IS NOT NULL`).
			Scan(ctx, &runs); err != nil {
			t.Fatalf("the run table has no snapshot: %v", err)
		}
		if findings != 0 || runs != 0 {
			t.Errorf("upgraded, %d findings and %d runs hold values nothing wrote", findings, runs)
		}
		t.Run("TheDeclarationsAreTheTablesTheMigrationsBuild", func(t *testing.T) {
			declared := migrations.StatementsV070(db.Server.Engine)
			if len(declared) != 2 {
				t.Errorf("v0.7.0 declares %d tables, want 2", len(declared))
			}
			declarationsAreBuilt(t, ctx, db, declared, madeElsewhere)
		})
	})
}
