// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v0120 is the migration v0.12.0 carries v0.11.0's schema across with.
const v0120 = 46

// A v0.11.0 database is upgraded, and the tables v0.12.0 changes are as it
// declares them.
func TestAV0110DatabaseUpgradesToV0120(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0110)
		dbtest.MigrateTo(t, db, v0120)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0120(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// A start that stopped after adding the issue dates and the checked scan's
// column carries on, and makes the index. On MySQL and MariaDB each column
// commits by itself.
func TestTheV0120UpgradeStepsOverColumnsAlreadyThere(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0110)
		for _, stmt := range []string{
			`ALTER TABLE "vulnerability" ADD COLUMN "published_at" ` + timestampOn(db.Server.Engine) + ` NULL`,
			`ALTER TABLE "vulnerability" ADD COLUMN "modified_at" ` + timestampOn(db.Server.Engine) + ` NULL`,
			`ALTER TABLE "vulnerability" ADD COLUMN "dates_asked_at" ` + timestampOn(db.Server.Engine) + ` NULL`,
		} {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("make what a stopped upgrade left: %v", err)
			}
		}
		dbtest.MigrateTo(t, db, v0120)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0120(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// timestampOn is how an engine declares a moment, as the migrations do.
func timestampOn(engine database.Engine) string {
	switch engine {
	case database.Postgres:
		return "TIMESTAMPTZ"
	case database.SQLite:
		return "DATETIME"
	default:
		return "DATETIME(6)"
	}
}
