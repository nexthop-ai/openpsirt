// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// measured is the table whose layout a measurement prints beside its timings.
// It is the largest table every measurement loads, and the one whose plans
// the measurements time.
const measured = "finding"

// layout is how a table sits on disk, as the planner reads it.
type layout struct {
	table string
	// pages is the table's size in pages as the planner's statistics hold
	// it: the table alone on PostgreSQL, the clustered index on MySQL and
	// MariaDB, which is where InnoDB keeps the rows.
	pages int64
	// order is the correlation between a column's values and the order the
	// rows sit in, for every column that leads an index. PostgreSQL alone
	// keeps it; InnoDB keeps rows in primary key order, so it has nothing to
	// correlate.
	order []correlation
}

type correlation struct {
	column string
	value  float64
}

func (l layout) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d pages", l.table, l.pages)
	if len(l.order) > 0 {
		b.WriteString("; correlation")
		for i, c := range l.order {
			sep := ","
			if i == 0 {
				sep = ""
			}
			fmt.Fprintf(&b, "%s %s %.2f", sep, c.column, c.value)
		}
	}
	return b.String()
}

// errNoLayout is the answer for SQLite, where each test copies a migrated
// file and no earlier test's layout can reach it.
var errNoLayout = errors.New("SQLite keeps no layout from one test to the next")

// readLayout reads the layout of one table from statistics already gathered.
//
// A table with no statistics is refused rather than reported as no pages and
// no correlation, which reads the same as a table that is empty.
func readLayout(ctx context.Context, db *database.DB, table string) (layout, error) {
	l := layout{table: table}
	switch db.Server.Engine {
	case database.SQLite:
		return l, errNoLayout
	case database.Postgres:
		// reltuples is -1 until the table is first analyzed or vacuumed, and
		// relpages is then the zero a freshly created table also has.
		var tuples float64
		var relation int64
		err := db.QueryRowContext(ctx, `
			SELECT "c"."oid", "c"."relpages", "c"."reltuples"
			FROM "pg_class" "c"
			JOIN "pg_namespace" "n" ON "n"."oid" = "c"."relnamespace"
			WHERE "n"."nspname" = current_schema() AND "c"."relname" = ?`,
			table).Scan(&relation, &l.pages, &tuples)
		if err != nil {
			return l, fmt.Errorf("read the pages of %s: %w", table, err)
		}
		if tuples < 0 {
			return l, fmt.Errorf("%s has no statistics: analyze it first", table)
		}
		rows, err := db.QueryContext(ctx, `
			SELECT "a"."attname", "s"."correlation"
			FROM "pg_attribute" "a"
			JOIN "pg_stats" "s"
			  ON "s"."schemaname" = current_schema()
			 AND "s"."tablename" = ?
			 AND "s"."attname" = "a"."attname"
			 AND NOT "s"."inherited"
			WHERE "a"."attrelid" = ?
			  AND "a"."attnum" IN (
			    SELECT "i"."indkey"[0] FROM "pg_index" "i"
			    WHERE "i"."indrelid" = ?)
			ORDER BY "a"."attnum"`,
			table, relation, relation)
		if err != nil {
			return l, fmt.Errorf("read the correlation of %s: %w", table, err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var c correlation
			var value sql.NullFloat64
			if err := rows.Scan(&c.column, &value); err != nil {
				return l, err
			}
			// A column whose every value is null has no order to correlate.
			if value.Valid {
				c.value = value.Float64
				l.order = append(l.order, c)
			}
		}
		if err := rows.Err(); err != nil {
			return l, err
		}
		if len(l.order) == 0 {
			return l, fmt.Errorf("%s has no column leading an index with a correlation: "+
				"it holds no rows, or was not analyzed", table)
		}
		return l, nil
	default:
		// The size the optimizer reads, which ANALYZE TABLE refreshes.
		var bytes, page sql.NullInt64
		err := db.QueryRowContext(ctx,
			`SELECT "data_length", @@innodb_page_size FROM "information_schema"."tables"
			 WHERE "table_schema" = DATABASE() AND "table_name" = ?`,
			table).Scan(&bytes, &page)
		if err != nil {
			return l, fmt.Errorf("read the pages of %s: %w", table, err)
		}
		if !bytes.Valid || !page.Valid || page.Int64 == 0 {
			return l, fmt.Errorf("%s has no statistics: analyze it first", table)
		}
		l.pages = bytes.Int64 / page.Int64
		return l, nil
	}
}

// fresh empties a database so that what is loaded next is laid out as a load
// into a newly migrated database is.
//
// A deleted row's space stays in the table and is filled again by the next
// load, wherever it sits. On PostgreSQL a table emptied by deleting and loaded
// again spreads over more pages, in an order its identifiers no longer
// follow. On MySQL and MariaDB the clustered index takes a number of pages that
// varies with how far the server has purged the deleted rows, where a fresh
// load takes the same number every time. Truncating gives each table new,
// empty storage.
//
// SQLite copies a migrated file per test, so it is emptied the ordinary way.
func fresh(ctx context.Context, db *database.DB) error {
	quoted := make([]string, len(tables))
	for i, table := range tables {
		quoted[i] = `"` + table + `"`
	}
	switch db.Server.Engine {
	case database.SQLite:
		return clear(ctx, db)
	case database.Postgres:
		// One statement naming every table, so no foreign key between two of
		// them refuses it.
		if _, err := db.ExecContext(ctx, "TRUNCATE "+strings.Join(quoted, ", ")); err != nil {
			return fmt.Errorf("truncate every table: %w", err)
		}
		return nil
	default:
		// MySQL and MariaDB truncate one table a statement, and refuse a
		// table another one references while the session checks foreign
		// keys. The checks are suspended on one connection and restored
		// before it goes back to the pool.
		conn, err := db.Conn(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		if _, err := conn.ExecContext(ctx, "SET SESSION foreign_key_checks = 0"); err != nil {
			return fmt.Errorf("suspend foreign key checks: %w", err)
		}
		var failed error
		for _, table := range quoted {
			if _, err := conn.ExecContext(ctx, "TRUNCATE TABLE "+table); err != nil {
				failed = fmt.Errorf("truncate %s: %w", table, err)
				break
			}
		}
		if _, err := conn.ExecContext(ctx, "SET SESSION foreign_key_checks = 1"); err != nil {
			// A connection left without its checks goes on serving the pool,
			// so it is discarded rather than returned.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			return fmt.Errorf("restore foreign key checks: %w", err)
		}
		return failed
	}
}
