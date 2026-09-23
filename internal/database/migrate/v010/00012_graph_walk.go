// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package v010

import (
	"context"
	"database/sql"
)

func init() {
	register(upGraphWalk, downGraphWalk)
}

// The index the tree walk needs to count findings per component.
//
// Browsing the dependency graph asks, for every component one step below where
// you are, how many findings are open against it — which is what makes
// descending follow the findings rather than being exploration. `finding`
// carried five indexes and none of them contained `component_id`, so that
// count had no way in: the planner took `finding_open_idx (target_id,
// closed_at)`, which on a real build matches **every open finding for the
// target**, and filtered them one at a time.
//
// Measured on a switch operating-system image — 441,108 open findings, and a
// root with 5,270 components directly under it, so the count runs 5,270 times:
// 637 ms each, about 56 minutes for one column of one screen. The request that
// asked for it was long gone; nothing stops a walk that is already running, so
// each attempt left another one behind and the process was still saturating
// three cores ninety minutes later. With this index the same count is 0.067 ms
// and the column is 0.35 s.
//
// The column order is the one the query binds: the target is always known, the
// component is the correlation, and `closed_at IS NULL` is what "open" means.
// It also serves the plain "what is open against this component here" lookup,
// which is the same prefix without the last column.
func upGraphWalk(ctx context.Context, tx *sql.Tx) error {
	statements := []string{
		`CREATE INDEX "finding_component_idx" ON "finding" ("target_id", "component_id", "closed_at")`,
	}
	return apply(ctx, tx, statements)
}

func downGraphWalk(ctx context.Context, tx *sql.Tx) error {
	return dropIndex(ctx, tx, "finding", "finding_component_idx")
}
