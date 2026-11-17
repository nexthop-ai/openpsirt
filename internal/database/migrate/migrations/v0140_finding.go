// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// findingV0140 is v0.14.0's declaration of the finding table, and the indexes
// it makes.
//
// v0.11.0's, with an index holding every column the trend and the burndown
// reduce one build's findings to moments by, in the order they group on: one
// build's findings are a range of it, read without the table and grouped in
// order. Fifteen builds of a real image, 3.6 million findings: 0.4 s through
// it against 3.0 s without it on PostgreSQL
// (design-docs/analytics-measurements.md § Many builds).
func findingV0140(t *columnTypes) []string {
	return append(findingV0110(t),
		`CREATE INDEX "finding_moment_idx" ON "finding" ("build_id", "vulnerability_id", "component_id", "opened_at", "opened_run_id", "closed_at", "closed_because", "kind", "visibility")`)
}

// findingMomentV0140 makes the index of each build's findings by moment.
func findingMomentV0140(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	return u.index(findingV0140(u.t), "finding", "finding_moment_idx")
}
