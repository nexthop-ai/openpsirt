// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// findingV090 is v0.9.0's declaration of the finding table, and the indexes it
// makes.
//
// v0.8.0's, without the moment anything about a finding last moved: nothing
// read it. Derived from v0.8.0's declaration, which v0.8.0's record of its
// schema holds.
func findingV090(t *columnTypes) []string {
	statements := findingV080(t)
	column := "\n\t\t\t" + `"last_changed_at"  ` + t.timestamp + ` NOT NULL,`
	if !strings.Contains(statements[0], column) {
		panic("the declaration being changed has no column last_changed_at")
	}
	statements[0] = strings.Replace(statements[0], column, "", 1)
	return statements
}

// dropLastChangedV090 removes the moment anything about a finding last moved.
//
// SQLite rebuilds the table from its declaration; the others drop the column.
// A table whose column is already gone is stepped over, so a start resuming
// on MySQL or MariaDB after this step committed runs on past it.
func dropLastChangedV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	has, err := u.hasColumn("finding", "last_changed_at")
	if err != nil || !has {
		return err
	}
	return u.change(findingV090(t), change{table: "finding", drop: []string{"last_changed_at"}})
}
