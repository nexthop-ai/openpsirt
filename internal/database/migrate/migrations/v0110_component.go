// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/uptrace/bun"
)

// componentTextV0110 is every text column of a component a producer states,
// which v0.11.0 stores with surrounding space taken off.
var componentTextV0110 = []string{"purl", "cpe", "name", "version", "upstream_name", "upstream_version",
	"supplier", "license"}

// componentBatchV0110 is how many components one read of the trimming step
// takes.
const componentBatchV0110 = 5_000

// trimComponentsV0110 takes surrounding space off every text a component row
// holds from a producer, as v0.11.0 stores it. A decision is keyed on a
// trimmed version, and MySQL and MariaDB ignore a trailing space in an
// equality where PostgreSQL, SQLite and the application do not, so a row
// stored untrimmed matches its decisions on two engines of four.
//
// Read and written in Go, in batches by identifier, because surrounding space
// is what Go's trimming removes, which no engine's TRIM matches: each trims
// the space character alone. A row already trimmed is read and left alone, so
// a start after one that stopped part way writes only what the first missed.
// Identity already reads the name and version trimmed, so no identity moves.
func trimComponentsV0110(ctx context.Context, tx bun.Tx) error {
	return trimComponentsInBatchesV0110(ctx, tx, componentBatchV0110)
}

// trimComponentsInBatchesV0110 trims as trimComponentsV0110 does, reading
// batch components at a time.
func trimComponentsInBatchesV0110(ctx context.Context, tx bun.Tx, batch int) error {
	columns := `"id", "` + strings.Join(componentTextV0110, `", "`) + `"`
	for after := int64(0); ; {
		rows, err := tx.QueryContext(ctx, `SELECT `+columns+` FROM "component"
			WHERE "id" > ? ORDER BY "id" LIMIT ?`, after, batch)
		if err != nil {
			return fmt.Errorf("read the components to trim: %w", err)
		}
		type spaced struct {
			id     int64
			values []sql.NullString
		}
		var found []spaced
		read := 0
		for rows.Next() {
			row := spaced{values: make([]sql.NullString, len(componentTextV0110))}
			into := []any{&row.id}
			for i := range row.values {
				into = append(into, &row.values[i])
			}
			if err := rows.Scan(into...); err != nil {
				_ = rows.Close()
				return fmt.Errorf("read a component to trim: %w", err)
			}
			read++
			after = row.id
			changed := false
			for i, v := range row.values {
				if trimmed := strings.TrimSpace(v.String); v.Valid && trimmed != v.String {
					row.values[i].String = trimmed
					changed = true
				}
			}
			if changed {
				found = append(found, row)
			}
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("read the components to trim: %w", err)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("read the components to trim: %w", err)
		}
		for _, row := range found {
			set := make([]string, len(componentTextV0110))
			args := make([]any, 0, len(componentTextV0110)+1)
			for i, column := range componentTextV0110 {
				set[i] = `"` + column + `" = ?`
				args = append(args, row.values[i])
			}
			args = append(args, row.id)
			if _, err := tx.ExecContext(ctx, `UPDATE "component" SET `+strings.Join(set, ", ")+
				` WHERE "id" = ?`, args...); err != nil {
				return fmt.Errorf("trim component %d: %w", row.id, err)
			}
		}
		if read < batch {
			return nil
		}
	}
}
