// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// selfReferences is the column of each table that points at a row of the same
// table. MySQL and MariaDB enforce such a reference during a bulk delete even
// though every row is going, and PostgreSQL and SQLite happen not to, so the
// column is emptied on the rows being deleted first.
var selfReferences = map[string]string{
	// A tag points at the branch it was cut from.
	"branch_or_tag": "parent_id",
	// A decision points at the decision it was derived from.
	"decision": "derived_from",
	// A window points at the window it counts from.
	"response_window": "from_window_id",
}

// keptExtraBound is how many rows past the kept ones a seeded table may hold
// for a test to be undone row by row. A table past it is emptied and written
// back whole, because reading it to compare costs more than that.
const keptExtraBound = keptBatch

// errNotUndone is a database a test changed in a way reconcile leaves to
// emptying and writing back.
var errNotUndone = errors.New("the rows a test left are emptied and written back instead")

// reconcile undoes what a test did to a server database the seed wrote kept
// into, in one transaction: a table holding no kept row is emptied, and each
// table that holds kept rows has the rows the test added deleted, the kept
// rows it changed written back in place, and the kept rows it deleted written
// again.
//
// It exists because emptying the seeded tables costs most of a test's start
// on PostgreSQL: every row deleted from a table fires a check on every foreign
// key referencing it, and most tables reference a person. Rows a test left as the seed
// wrote them are never touched.
//
// The order is what keeps a kept row from being changed by the deletes. Kept
// rows written again come first, parents first, then the changed rows, so
// every kept row holds the values it was read with and points only at kept
// rows; then the deletes, children first, reach no kept row, by a foreign
// key's action or otherwise. A table without an identifier is emptied and
// written back whole where it differs, which is safe because no foreign key
// references one. Anything else, a column the test added or a unique value a
// kept row needs that an added row holds, fails the transaction, and the
// caller empties and writes back instead.
func reconcile(ctx context.Context, db *database.DB, kept []keptTable) error {
	keptBy := make(map[string]keptTable, len(kept))
	for _, table := range kept {
		keptBy[table.name] = table
	}
	return database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
		held, err := occupied(ctx, db, tx, tables)
		if err != nil {
			return err
		}
		var (
			missing []keptTable
			changed []changedRow
			whole   []keptTable
			rewrite = map[string]bool{}
			extra   = map[string][]int64{}
		)
		for _, k := range kept {
			if !held[k.name] {
				missing = append(missing, k)
				continue
			}
			now, err := readTableUpTo(ctx, tx, k.name, len(k.rows)+keptExtraBound+1)
			if err != nil {
				return err
			}
			if !slices.Equal(now.columns, k.columns) || len(now.rows) > len(k.rows)+keptExtraBound {
				return errNotUndone
			}
			id := slices.Index(k.columns, "id")
			if id < 0 {
				if !sameRowsUnordered(now.rows, k.rows) {
					whole = append(whole, k)
					rewrite[k.name] = true
				}
				continue
			}
			d, err := differences(k, now, id)
			if err != nil {
				return err
			}
			if len(d.missing) > 0 {
				missing = append(missing, keptTable{name: k.name, columns: k.columns, rows: d.missing})
			}
			changed = append(changed, d.changed...)
			if len(d.extra) > 0 {
				extra[k.name] = d.extra
			}
		}

		if err := insertKept(ctx, tx, missing); err != nil {
			return err
		}
		for _, c := range changed {
			if err := c.write(ctx, tx); err != nil {
				return err
			}
		}
		for _, table := range tables {
			_, isKept := keptBy[table]
			var err error
			switch {
			case !isKept && held[table], rewrite[table]:
				err = deleteRows(ctx, tx, table, nil)
			case len(extra[table]) > 0:
				err = deleteRows(ctx, tx, table, extra[table])
			}
			if err != nil {
				return err
			}
		}
		return insertKept(ctx, tx, whole)
	})
}

// tableDiff is how one table a test touched differs from its kept rows.
type tableDiff struct {
	missing [][]any
	changed []changedRow
	extra   []int64
}

// differences compares a table's rows now with its kept rows, matched by the
// identifier in column id.
func differences(k, now keptTable, id int) (tableDiff, error) {
	var d tableDiff
	keptByID := make(map[int64][]any, len(k.rows))
	for _, row := range k.rows {
		key, ok := row[id].(int64)
		if !ok {
			return d, fmt.Errorf("an identifier of %s reads as %T, not a whole number", k.name, row[id])
		}
		keptByID[key] = row
	}
	present := make(map[int64]bool, len(now.rows))
	for _, row := range now.rows {
		key, ok := row[id].(int64)
		if !ok {
			return d, fmt.Errorf("an identifier of %s reads as %T, not a whole number", k.name, row[id])
		}
		want, isKept := keptByID[key]
		if !isKept {
			d.extra = append(d.extra, key)
			continue
		}
		present[key] = true
		var columns []string
		var values []any
		for i := range want {
			if !sameValue(want[i], row[i]) {
				columns = append(columns, k.columns[i])
				values = append(values, want[i])
			}
		}
		if len(columns) > 0 {
			d.changed = append(d.changed, changedRow{table: k.name, id: key, columns: columns, values: values})
		}
	}
	for _, row := range k.rows {
		if !present[row[id].(int64)] { //nolint:forcetypeassert // every kept identifier was asserted above
			d.missing = append(d.missing, row)
		}
	}
	return d, nil
}

// changedRow is a kept row a test changed, and the values it is written back
// with: only the columns that differ, so a foreign key nobody moved is not
// checked again.
type changedRow struct {
	table   string
	id      int64
	columns []string
	values  []any
}

func (c changedRow) write(ctx context.Context, tx bun.Tx) error {
	set := make([]string, len(c.columns))
	for i, column := range c.columns {
		set[i] = `"` + column + `" = ?`
	}
	result, err := tx.ExecContext(ctx, `UPDATE "`+c.table+`" SET `+strings.Join(set, ", ")+` WHERE "id" = ?`,
		append(slices.Clone(c.values), c.id)...)
	if err != nil {
		return fmt.Errorf("write back seeded row %d of %s: %w", c.id, c.table, err)
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("write back seeded row %d of %s: %d rows matched (%w)", c.id, c.table, n, err)
	}
	return nil
}

// deleteRows deletes the rows of table with the given identifiers, or every
// row where there are none, emptying a reference to the same table on them
// first.
func deleteRows(ctx context.Context, tx bun.Tx, table string, ids []int64) error {
	where, args := "", []any(nil)
	if ids != nil {
		where, args = ` WHERE "id" IN (?)`, []any{bun.List(ids)}
	}
	if column, ok := selfReferences[table]; ok {
		if _, err := tx.ExecContext(ctx, `UPDATE "`+table+`" SET "`+column+`" = NULL`+where, args...); err != nil {
			return fmt.Errorf("detach %s from its own table: %w", table, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM "`+table+`"`+where, args...); err != nil {
		return fmt.Errorf("clear %s: %w", table, err)
	}
	return nil
}

// insertKept writes kept rows, a statement per batch, in the order given.
func insertKept(ctx context.Context, tx bun.Tx, kept []keptTable) error {
	for _, table := range kept {
		quoted := make([]string, len(table.columns))
		for i, column := range table.columns {
			quoted[i] = `"` + column + `"`
		}
		row := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(table.columns)), ", ") + ")"
		for start := 0; start < len(table.rows); start += keptBatch {
			batch := table.rows[start:min(start+keptBatch, len(table.rows))]
			values := make([]string, len(batch))
			args := make([]any, 0, len(batch)*len(table.columns))
			for i, r := range batch {
				values[i] = row
				args = append(args, r...)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO "`+table.name+`" (`+strings.Join(quoted, ", ")+
				`) VALUES `+strings.Join(values, ", "), args...); err != nil {
				return fmt.Errorf("write back the seeded rows of %s: %w", table.name, err)
			}
		}
	}
	return nil
}

// sameValue is whether two column values a driver read are the same value: a
// moment by its instant and bytes by their content, whatever location or
// buffer the driver handed them in.
func sameValue(a, b any) bool {
	switch x := a.(type) {
	case time.Time:
		y, ok := b.(time.Time)
		return ok && x.Equal(y)
	case []byte:
		y, ok := b.([]byte)
		return ok && bytes.Equal(x, y)
	}
	return reflect.DeepEqual(a, b)
}

// sameRowsUnordered is whether two reads of a table without an identifier hold
// the same rows, in whatever order each came back.
func sameRowsUnordered(a, b [][]any) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, row := range a {
		found := -1
		for j, other := range b {
			if !used[j] && slices.EqualFunc(row, other, sameValue) {
				found = j
				break
			}
		}
		if found < 0 {
			return false
		}
		used[found] = true
	}
	return true
}

// occupancy is the statement asking which tables hold rows, prepared once per
// harness pool and kept for the binary: it is a scalar subquery per table, and
// planning it is 37 ms on a PostgreSQL connection that has not seen it and
// about 3 ms on one that has, against a fraction of that to run it.
var occupancy = map[*sql.DB]*sql.Stmt{}

// occupancyFor is the prepared occupancy statement for db's pool, or nil where
// db is not a harness server pool: a test's own connection is closed when the
// test ends, and a statement kept for it would outlive it.
func occupancyFor(ctx context.Context, db *database.DB) (*sql.Stmt, error) {
	serverMu.Lock()
	defer serverMu.Unlock()
	pool, ok := serverDBs[db.Server.Engine]
	if !ok || pool.DB.DB != db.DB.DB {
		return nil, nil
	}
	if stmt := occupancy[pool.DB.DB]; stmt != nil {
		return stmt, nil
	}
	stmt, err := pool.DB.DB.PrepareContext(ctx, occupancyQuery(tables))
	if err != nil {
		return nil, fmt.Errorf("prepare the question of which tables hold rows: %w", err)
	}
	occupancy[pool.DB.DB] = stmt
	return stmt, nil
}
