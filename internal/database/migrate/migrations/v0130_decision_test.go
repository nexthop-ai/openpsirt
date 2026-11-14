// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A v0.12.0 database upgrades to v0.13.0's declarations, from the start and
// from a start on MySQL or MariaDB that stopped after the withdrawer's column
// committed and before its key.
func TestAV0120DatabaseGainsTheWithdrawerFromEveryStop(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		name := "from the start"
		if stopped {
			name = "after the withdrawer's column"
		}
		t.Run(name, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				if stopped && db.Server.Engine == database.SQLite {
					t.Skip("SQLite changes a table in one transaction, so it never stops there")
				}
				ctx := t.Context()
				dbtest.Empty(t, db)
				dbtest.MigrateTo(t, db, v0120)
				if stopped {
					if err := migrations.StopV0130AfterEndedByColumn(ctx, db); err != nil {
						t.Fatal(err)
					}
				}
				dbtest.MigrateTo(t, db, v0130)
				declarationsAreBuilt(t, ctx, db, migrations.StatementsV0130(db.Server.Engine))
				leaveAtLatest(t, ctx, db)
			})
		})
	}
}
