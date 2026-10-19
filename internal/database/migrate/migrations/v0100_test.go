// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v0100 is the migration v0.10.0 carries v0.9.0's schema across with.
const v0100 = 44

// A v0.9.0 database is upgraded, and its finding table carries the indexes
// v0.10.0 declares.
func TestAV090DatabaseUpgradesToV0100(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v090)
		dbtest.MigrateTo(t, db, v0100)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0100(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// An index the upgrade makes is replaced where the database already holds it.
// On MySQL and MariaDB a stopped upgrade leaves the indexes it had made, and
// the next start runs it from the top.
func TestTheV0100UpgradeRunsAgainOverIndexesItMade(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v090)
		if _, err := db.ExecContext(ctx,
			`CREATE INDEX "finding_opened_run_idx" ON "finding" ("target_id", "opened_run_id")`); err != nil {
			t.Fatalf("make what a stopped upgrade left: %v", err)
		}
		dbtest.MigrateTo(t, db, v0100)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0100(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// A start that stopped after adding who declined a statement and before adding
// when is carried on: on MySQL and MariaDB each column commits by itself.
func TestTheV0100UpgradeAddsWhatAStoppedStartLeftOut(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v090)
		if _, err := db.ExecContext(ctx,
			`ALTER TABLE "vex_statement" ADD COLUMN "declined_at" `+timestampOf(db)+` NULL`); err != nil {
			t.Fatalf("make what a stopped upgrade left: %v", err)
		}
		dbtest.MigrateTo(t, db, v0100)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0100(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// timestampOf is how an engine declares a moment.
func timestampOf(db *database.DB) string {
	switch db.Server.Engine {
	case database.Postgres:
		return "TIMESTAMPTZ"
	case database.MySQL, database.MariaDB:
		return "DATETIME(6)"
	}
	return "DATETIME"
}
