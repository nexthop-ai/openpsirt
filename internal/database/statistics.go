// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strings"

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

// Analyzed is what AnalyzeEveryTable did: how many tables it analyzed, and
// the tables it stepped over because something held them.
type Analyzed struct {
	Tables  int
	Skipped []string
}

// lockWait bounds how long MySQL and MariaDB wait for a table's metadata lock
// before an analysis steps over the table. An analysis needs only a shared
// lock, so it waits only behind a schema change holding or queued for an
// exclusive one, and without a bound it waits for the server's default of a
// year.
const lockWait = "1"

// AnalyzeEveryTable asks the engine to refresh the planner's statistics of
// every table in the database now. On SQLite it is RefreshStatistics, which
// analyzes the whole file and counts no tables.
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
// for more than four hours. Analyzed, the same statement takes 5 ms. Every
// table of that database analyzes in 140 ms.
//
// A table something holds is stepped over rather than waited for, so that
// another replica's schema change or vacuum never holds a start. PostgreSQL
// skips it in the statement and says so only as a warning, so a skipped table
// is reported there as analyzed. MySQL 8.4 and MariaDB 11.4 analyze a table
// beside a long query reading it without waiting, and leave the next query
// waiting for nothing.
func AnalyzeEveryTable(ctx context.Context, db *DB) (Analyzed, error) {
	if db.Server.Engine == SQLite {
		return Analyzed{}, RefreshStatistics(ctx, db)
	}
	// One connection, so that the bound on waiting set below reaches every
	// statement, and is put back before the connection returns to the pool.
	conn, err := db.Conn(ctx)
	if err != nil {
		return Analyzed{}, fmt.Errorf("reserve a connection to analyze with: %w", err)
	}
	defer func() { _ = conn.Close() }()

	var names []string
	listing := conn.NewRaw(`SELECT "table_name" AS "name" FROM "information_schema"."tables"
		WHERE "table_schema" = DATABASE() AND "table_type" = 'BASE TABLE'`)
	if db.Server.Engine == Postgres {
		listing = conn.NewRaw(`SELECT "tablename" AS "name" FROM "pg_catalog"."pg_tables"
			WHERE "schemaname" = current_schema()`)
	}
	if err := listing.Scan(ctx, &names); err != nil {
		return Analyzed{}, fmt.Errorf("list the tables to analyze: %w", err)
	}

	var done Analyzed
	if db.Server.Engine == Postgres {
		for _, name := range names {
			if _, err := conn.ExecContext(ctx, "ANALYZE (SKIP_LOCKED) ?", bun.Ident(name)); err != nil {
				return done, fmt.Errorf("refresh the statistics of %s: %w", name, err)
			}
			done.Tables++
		}
		return done, nil
	}

	if _, err := conn.ExecContext(ctx, "SET SESSION lock_wait_timeout = "+lockWait); err != nil {
		return done, fmt.Errorf("bound the wait to analyze: %w", err)
	}
	defer func() {
		// A connection that cannot be put back is closed rather than pooled
		// with the bound still on it.
		if _, err := conn.ExecContext(context.WithoutCancel(ctx),
			"SET SESSION lock_wait_timeout = DEFAULT"); err != nil {
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	for _, name := range names {
		held, err := analyzeTable(ctx, conn, name)
		if err != nil {
			return done, err
		}
		if held {
			done.Skipped = append(done.Skipped, name)
			continue
		}
		done.Tables++
	}
	return done, nil
}

// analyzeTable refreshes the statistics of one table on MySQL or MariaDB, and
// reports whether it was stepped over because something held it.
//
// Both answer with rows rather than an error, the type of the row saying what
// happened, so the answer is read. The type is spelled "Error" on both.
func analyzeTable(ctx context.Context, conn bun.Conn, table string) (bool, error) {
	var rows []struct {
		Table   string `bun:"Table"`
		Op      string `bun:"Op"`
		Kind    string `bun:"Msg_type"`
		Message string `bun:"Msg_text"`
	}
	if err := conn.NewRaw("ANALYZE TABLE ?", bun.Ident(table)).Scan(ctx, &rows); err != nil {
		return false, fmt.Errorf("refresh the statistics of %s: %w", table, err)
	}
	for _, row := range rows {
		if !strings.EqualFold(row.Kind, "error") {
			continue
		}
		if strings.Contains(row.Message, "Lock wait timeout") {
			return true, nil
		}
		return false, fmt.Errorf("refresh the statistics of %s: %s", table, row.Message)
	}
	return false, nil
}
