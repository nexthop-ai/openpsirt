// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// keptTable is every row of one table, as the driver hands each column back.
type keptTable struct {
	name    string
	columns []string
	rows    [][]any
}

// keptBatch is the most rows one statement writes back. The seeds hold tens
// of rows a table; the bound keeps a larger one under every engine's limit on
// a statement's parameters.
const keptBatch = 200

// keep reads back every row of every table holding one, parents before the
// rows that reference them, so restore can write them in the order read.
//
// The rows of a table are ordered by identifier where it has one, because a
// table referencing itself, a tag pointing at its branch, has the row
// referenced written first.
func keep(ctx context.Context, db *database.DB) ([]keptTable, error) {
	var kept []keptTable
	err := database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
		kept = nil
		held, err := occupied(ctx, tx, tables)
		if err != nil {
			return err
		}
		for _, table := range slices.Backward(tables) {
			if !held[table] {
				continue
			}
			read, err := readTable(ctx, tx, table)
			if err != nil {
				return err
			}
			kept = append(kept, read)
		}
		return nil
	})
	return kept, err
}

// readTable reads every row of one table.
func readTable(ctx context.Context, tx bun.Tx, table string) (keptTable, error) {
	rows, err := tx.QueryContext(ctx, `SELECT * FROM "`+table+`"`)
	if err != nil {
		return keptTable{}, fmt.Errorf("read %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	columns, err := rows.Columns()
	if err != nil {
		return keptTable{}, fmt.Errorf("read the columns of %s: %w", table, err)
	}
	read := keptTable{name: table, columns: columns}
	for rows.Next() {
		row := make([]any, len(columns))
		into := make([]any, len(columns))
		for i := range row {
			into[i] = &row[i]
		}
		if err := rows.Scan(into...); err != nil {
			return keptTable{}, fmt.Errorf("read a row of %s: %w", table, err)
		}
		read.rows = append(read.rows, row)
	}
	if err := rows.Err(); err != nil {
		return keptTable{}, fmt.Errorf("read %s: %w", table, err)
	}
	if id := slices.Index(columns, "id"); id >= 0 {
		var failed error
		slices.SortStableFunc(read.rows, func(a, b []any) int {
			x, xok := a[id].(int64)
			y, yok := b[id].(int64)
			if !xok || !yok {
				failed = fmt.Errorf("an identifier of %s reads as %T, not a whole number", table, a[id])
				return 0
			}
			return cmp.Compare(x, y)
		})
		if failed != nil {
			return keptTable{}, failed
		}
	}
	return read, nil
}

// restore writes kept rows back into an emptied database, in one transaction,
// with the identifiers they were read with. Every engine's identifier counter
// is past them: emptying deletes rows and leaves the counter where the seed
// moved it, so a row a test adds takes an identifier no kept row holds.
func restore(ctx context.Context, db *database.DB, kept []keptTable) error {
	return database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
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
	})
}
