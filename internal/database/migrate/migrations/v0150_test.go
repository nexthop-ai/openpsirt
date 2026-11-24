// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v0150 is the migration v0.15.0 carries v0.14.0's schema across with.
const v0150 = 49

// The v0.15.0 upgrade builds what v0.15.0 declares, over a database v0.14.0
// built and over one it has already run on.
func TestTheV0150UpgradeBuildsItsDeclarations(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0140)
		dbtest.MigrateTo(t, db, v0150)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0150(db.Server.Engine))
		unrecordAt(t, db, v0150)
		dbtest.MigrateTo(t, db, v0150)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0150(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// A run v0.14.0 recorded is upgraded as one that recorded no match sources,
// since a finding it left unchanged holds none whatever it was matched on.
func TestTheV0150UpgradeCountsNoEarlierRunAsRecordingSources(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0140)
		s := seedRowsV0120(t, db)
		s.exec(`INSERT INTO "scan_run" ("build_id", "scanner", "ran_here", "started_at") VALUES (?, ?, ?, ?)`,
			s.build, "grype", true, s.at)
		dbtest.MigrateTo(t, db, v0150)
		var recorded []bool
		if err := db.DB.NewRaw(`SELECT "sources_recorded" FROM "scan_run"`).Scan(ctx, &recorded); err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 1 || recorded[0] {
			t.Errorf("a run v0.14.0 recorded reads as having recorded sources %v, want [false]", recorded)
		}
		leaveAtLatest(t, ctx, db)
	})
}
