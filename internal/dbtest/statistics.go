// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"errors"
	"fmt"
	"testing"
	"time"

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
// engine what a start asks it.
//
// It then prints the layout of the finding table on a server, which is what
// the plans being timed were chosen over.
func SettleStatistics(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	started := time.Now()
	done, err := database.AnalyzeEveryTable(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if db.Server.Engine != database.SQLite && done.Tables == 0 {
		t.Fatal("no table was analyzed, so no statistics were refreshed")
	}
	if len(done.Skipped) > 0 {
		t.Fatalf("tables held by something else were not analyzed: %v", done.Skipped)
	}
	t.Logf("statistics refreshed on %s over %d tables in %s", db.Server.Engine, done.Tables,
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

// EstimatedRows is how many rows the planner believes a table holds, read
// from where each engine keeps its statistics: PostgreSQL's catalog, InnoDB's
// persistent statistics on MySQL and MariaDB, and SQLite's statistics table.
// PostgreSQL answers -1 for a table never analyzed, and SQLite fails for one
// it has no row for.
func EstimatedRows(t *testing.T, db *database.DB, table string) float64 {
	t.Helper()
	ctx := t.Context()
	var estimate float64
	var err error
	switch db.Server.Engine {
	case database.Postgres:
		err = db.QueryRowContext(ctx, `SELECT "reltuples" FROM "pg_catalog"."pg_class"
			WHERE "relname" = ? AND "relnamespace" = current_schema()::regnamespace`, table).Scan(&estimate)
	case database.MySQL, database.MariaDB:
		err = db.QueryRowContext(ctx, `SELECT "n_rows" FROM "mysql"."innodb_table_stats"
			WHERE "database_name" = DATABASE() AND "table_name" = ?`, table).Scan(&estimate)
	default:
		var stat string
		err = db.QueryRowContext(ctx, `SELECT "stat" FROM "sqlite_stat1" WHERE "tbl" = ?`, table).Scan(&stat)
		if err == nil {
			_, err = fmt.Sscan(stat, &estimate)
		}
	}
	if err != nil {
		t.Fatalf("read the planner's estimate of %s: %v", table, err)
	}
	return estimate
}
