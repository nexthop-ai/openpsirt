// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v080 is the migration the untagged release carries v0.7.0's schema across
// with.
const v080 = 42

// A v0.7.0 database is upgraded, and its finding and decision tables carry the
// indexes v0.8.0 declares.
func TestAV070DatabaseUpgradesToV080(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v070)
		dbtest.MigrateTo(t, db, v080)

		declared := migrations.StatementsV080(db.Server.Engine)
		if len(declared) != 2 {
			t.Errorf("v0.8.0 declares %d tables, want 2", len(declared))
		}
		declarationsAreBuilt(t, ctx, db, declared)
	})
}

// An index the upgrade replaces is replaced whether the database holds it in
// v0.7.0's shape or already in v0.8.0's. On MySQL and MariaDB a stopped upgrade
// leaves the indexes it had made, and the next start runs it from the top.
func TestTheV080UpgradeRunsAgainOverIndexesItMade(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v070)
		drop := `DROP INDEX "finding_open_idx"`
		switch db.Server.Engine {
		case database.MySQL, database.MariaDB:
			drop += ` ON "finding"`
		}
		for _, stmt := range []string{
			drop,
			`CREATE INDEX "finding_open_idx" ON "finding" ("target_id", "closed_at", "due_at")`,
			`CREATE INDEX "decision_state_claim_idx" ON "decision" ("state", "claim_id")`,
		} {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("make what a stopped upgrade left: %v\n%s", err, stmt)
			}
		}
		dbtest.MigrateTo(t, db, v080)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV080(db.Server.Engine))
	})
}
