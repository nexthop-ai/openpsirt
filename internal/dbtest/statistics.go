// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// SettleStatistics brings the planner's statistics up to date with every table
// the schema declares, for a measurement taken after a bulk load.
//
// A server refreshes its statistics on its own once about a tenth of a table's
// rows have changed: PostgreSQL through autovacuum, MySQL and MariaDB through
// InnoDB's background statistics. A measurement queries seconds after loading,
// before either has run, and times a plan chosen from an empty table's
// estimates — minutes where the settled plan takes a second. This asks each
// server to do now what it does on its own shortly after.
//
// SQLite is left as it is. It gathers statistics only when asked, and nothing
// in a deployment asks, so a SQLite deployment plans without them for as long
// as it runs; a measurement with them would describe a database nobody has.
func SettleStatistics(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	started := time.Now()
	switch db.Server.Engine {
	case database.SQLite:
		return
	case database.Postgres:
		for _, table := range tables {
			if _, err := db.ExecContext(ctx, "ANALYZE ?", bun.Ident(table)); err != nil {
				t.Fatalf("refresh the statistics of %s: %v", table, err)
			}
		}
	default:
		// MySQL and MariaDB answer with a row per table rather than an error,
		// so the answer is read: a table the server could not analyze says so
		// there.
		for _, table := range tables {
			var rows []struct {
				Table   string `bun:"Table"`
				Op      string `bun:"Op"`
				Kind    string `bun:"Msg_type"`
				Message string `bun:"Msg_text"`
			}
			if err := db.NewRaw("ANALYZE TABLE ?", bun.Ident(table)).Scan(ctx, &rows); err != nil {
				t.Fatalf("refresh the statistics of %s: %v", table, err)
			}
			for _, row := range rows {
				if row.Kind == "error" {
					t.Fatalf("refresh the statistics of %s: %s", table, row.Message)
				}
			}
		}
	}
	if len(tables) == 0 {
		t.Fatal("no tables were named, so no statistics were refreshed")
	}
	t.Logf("statistics refreshed on %s over %d tables in %s", db.Server.Engine, len(tables),
		time.Since(started).Round(time.Millisecond))
}
