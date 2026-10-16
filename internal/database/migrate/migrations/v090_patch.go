// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// patchBranchV090 is v0.9.0's declaration of the patch-branch tables.
//
// The baseline's, with when a repository's last visit ended, however it
// ended. Derived from the baseline's declaration, which v0.7.0's record of its
// schema holds.
func patchBranchV090(t *columnTypes) []string {
	statements := patchBranchBaseline(t)
	statements[0] = withColumn(statements[0], `"failed"       `+t.free+` NULL,`,
		`-- When the last visit ended, whether it reached the repository or
			-- not. With when it began, how long the visit held the pass,
			-- which is what each host's share of the pass is counted in.
			"ended_at"     `+t.timestamp+` NULL,`)
	return statements
}

// patchVisitEndV090 adds when a repository's last visit ended. No visit
// v0.8.0 recorded has an end, and each counts as having held the pass for no
// time until it is visited again.
func patchVisitEndV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	return u.change(patchBranchV090(t), change{table: "patch_repository",
		add: []added{{column: "ended_at"}}})
}
