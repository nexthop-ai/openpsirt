// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"
)

// fixStateUnscheduledV0130 renames the fix state a scanner reports as no fix
// scheduled, "wont-fix" in v0.12.0 and "unscheduled" in v0.13.0, on every
// finding and in every saved filter asking for it. A second start finds
// nothing left to rename.
func fixStateUnscheduledV0130(ctx context.Context, tx bun.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE "finding" SET "fix_state" = ? WHERE "fix_state" = ?`,
		"unscheduled", "wont-fix"); err != nil {
		return fmt.Errorf("rename the unscheduled fix state: %w", err)
	}
	type saved struct {
		id    int64
		query string
	}
	rows, err := tx.QueryContext(ctx, `SELECT "id", "query" FROM "saved_filter" WHERE "query" LIKE ?`,
		"%fix_state=wont-fix%")
	if err != nil {
		return fmt.Errorf("read the saved filters asking for a fix state: %w", err)
	}
	var found []saved
	for rows.Next() {
		var row saved
		if err := rows.Scan(&row.id, &row.query); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read a saved filter: %w", err)
		}
		if query := unscheduledQueryV0130(row.query); query != row.query {
			found = append(found, saved{row.id, query})
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("read the saved filters asking for a fix state: %w", err)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read the saved filters asking for a fix state: %w", err)
	}
	for _, row := range found {
		if _, err := tx.ExecContext(ctx, `UPDATE "saved_filter" SET "query" = ? WHERE "id" = ?`,
			row.query, row.id); err != nil {
			return fmt.Errorf("rename the fix state saved filter %d asks for: %w", row.id, err)
		}
	}
	return nil
}

// unscheduledQueryV0130 is a saved query string with each fix state of
// "wont-fix" asked as "unscheduled", and every other parameter as it was. The
// outcome of the same word is a decision, and is left alone.
func unscheduledQueryV0130(query string) string {
	parts := strings.Split(query, "&")
	for i, part := range parts {
		if part == "fix_state=wont-fix" {
			parts[i] = "fix_state=unscheduled"
		}
	}
	return strings.Join(parts, "&")
}
