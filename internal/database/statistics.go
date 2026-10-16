// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

// RefreshStatistics brings the planner's statistics up to date where the
// engine does not keep them itself.
//
// SQLite gathers none unless asked, and without them it chooses an index by
// how many columns an equality matches rather than by how many rows lie
// behind it. On a demo holding 361,429 findings, a review-queue statement
// took 4.0 s walking 297,405 of one component's findings when an index on
// the place reached the few it wanted in 0.6 ms, and the list of what is
// running out took 2.5 s where it takes 0.13 s. The servers keep statistics
// current on their own as rows change, so on them this does nothing; a start
// asks them once through AnalyzeEveryTable.
//
// A whole ANALYZE rather than the pragma that analyzes only a table that has
// grown several times over. A scan changes the shape of the tables more than
// their size: the demo's second build added a tenth to the findings, so the
// statistics went on describing every finding as under one build, and the
// findings list took 2.1 s where it takes 0.57 s. 0.66 s for the demo's
// 361,429 findings. Sampling the first rows of each index instead took 71 ms
// and misjudged which rows were assigned, which cost the assignments count
// 0.68 s.
func RefreshStatistics(ctx context.Context, db *DB) error {
	if db.Server.Engine != SQLite {
		return nil
	}
	if _, err := db.ExecContext(ctx, "ANALYZE"); err != nil {
		return fmt.Errorf("refresh the planner's statistics: %w", err)
	}
	// A connection reads the statistics when it opens and never again: the
	// one that ran the analysis plans from the new ones and every other open
	// connection from the old. So the idle ones are closed and the next
	// request opens one that reads these. The ones in use now are retired by
	// the connection lifetime the pool sets.
	// One connection ran the analysis and has nothing else to reach, and
	// closing it would drop an in-memory database with everything in it.
	if db.Stats().MaxOpenConnections == 1 {
		return nil
	}
	idle := db.Pool.MaxIdle
	if idle <= 0 {
		idle = db.Stats().MaxOpenConnections
	}
	if idle <= 0 {
		idle = 2 // the standard pool's own default
	}
	db.SetMaxIdleConns(0)
	db.SetMaxIdleConns(idle)
	return nil
}

// AnalyzeEveryTable asks the engine to refresh the planner's statistics of
// every table in the database now, and reports how many tables it analyzed.
// On SQLite it is RefreshStatistics, which analyzes the whole file and counts
// no tables.
//
// A server refreshes a table's statistics on its own once about a tenth of
// its rows have changed, in the background, and a database can still arrive
// with estimates that describe nothing: loaded before the background work
// ran, restored from elsewhere, or held by a server whose background work has
// stalled. A release's upgrade makes that worse rather than better on MySQL
// and MariaDB, because a table the upgrade rebuilds is analyzed as it is
// rebuilt and every other table keeps what it had. A v0.7.0 demo upgraded to
// v0.9.0's schema on MySQL 8.4 held 7,746 issues and 2 products under
// estimates of none, beside an accurate 2,202 decisions; the planner put the
// issues and products first as a cross product, and the decision audit ran
// for more than four hours. Analyzed, the same statement takes 5 ms. All 87
// tables of that database analyze in 140 ms.
func AnalyzeEveryTable(ctx context.Context, db *DB) (int, error) {
	if db.Server.Engine == SQLite {
		return 0, RefreshStatistics(ctx, db)
	}
	var names []string
	listing := db.NewRaw(`SELECT "table_name" AS "name" FROM "information_schema"."tables"
		WHERE "table_schema" = DATABASE() AND "table_type" = 'BASE TABLE'`)
	if db.Server.Engine == Postgres {
		listing = db.NewRaw(`SELECT "tablename" AS "name" FROM "pg_catalog"."pg_tables"
			WHERE "schemaname" = current_schema()`)
	}
	if err := listing.Scan(ctx, &names); err != nil {
		return 0, fmt.Errorf("list the tables to analyze: %w", err)
	}
	for _, name := range names {
		if err := analyzeTable(ctx, db, name); err != nil {
			return 0, err
		}
	}
	return len(names), nil
}

// analyzeTable refreshes the statistics of one table on a server.
func analyzeTable(ctx context.Context, db *DB, table string) error {
	if db.Server.Engine == Postgres {
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
