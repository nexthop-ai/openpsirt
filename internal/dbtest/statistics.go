// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"errors"
	"fmt"
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
// SQLite gathers statistics only when asked, and a deployment asks after every
// scan applies, so it is asked the same way here.
//
// It then prints the layout of the finding table on a server, which is what
// the plans being timed were chosen over.
func SettleStatistics(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	started := time.Now()
	switch db.Server.Engine {
	case database.SQLite:
		if err := database.RefreshStatistics(ctx, db); err != nil {
			t.Fatal(err)
		}
	default:
		for _, table := range tables {
			if err := analyze(ctx, db, table); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(tables) == 0 {
		t.Fatal("no tables were named, so no statistics were refreshed")
	}
	t.Logf("statistics refreshed on %s over %d tables in %s", db.Server.Engine, len(tables),
		time.Since(started).Round(time.Millisecond))

	// The layout a plan was chosen over, printed beside the timings that
	// plan produced. Two runs reading different layouts are two different
	// measurements, and this is where that shows.
	l, err := readLayout(ctx, db, measured)
	if errors.Is(err, errNoLayout) {
		return
	}
	if err != nil {
		t.Fatalf("read the layout a measurement runs over: %v", err)
	}
	t.Logf("layout on %s of %s", db.Server.Engine, l)
}

// analyze refreshes the statistics of one table on a server.
func analyze(ctx context.Context, db *database.DB, table string) error {
	if db.Server.Engine == database.Postgres {
		if _, err := db.ExecContext(ctx, "ANALYZE ?", bun.Ident(table)); err != nil {
			return fmt.Errorf("refresh the statistics of %s: %w", table, err)
		}
		return nil
	}
	// MySQL and MariaDB answer with a row per table rather than an error, so
	// the answer is read: a table the server could not analyze says so there.
	var rows []struct {
		Table   string `bun:"Table"`
		Op      string `bun:"Op"`
		Kind    string `bun:"Msg_type"`
		Message string `bun:"Msg_text"`
	}
	if err := db.NewRaw("ANALYZE TABLE ?", bun.Ident(table)).Scan(ctx, &rows); err != nil {
		return fmt.Errorf("refresh the statistics of %s: %w", table, err)
	}
	for _, row := range rows {
		if row.Kind == "error" {
			return fmt.Errorf("refresh the statistics of %s: %s", table, row.Message)
		}
	}
	return nil
}
