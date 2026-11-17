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
// v0.11.0's, with three indexes holding one more column each, so the reads
// they serve take no row from the table. Fifteen builds of a real image, 3.6
// million findings, on PostgreSQL (design-docs/analytics-measurements.md
// § Many builds):
//
//   - The group index holds the run that opened a finding, last, so it holds
//     every column the trend and the burndown reduce one build's findings to
//     moments by: the moments in 0.46 s against 1.5 s without it.
//   - The opened-run and closed-run indexes hold why a finding closed, which
//     tells a check's match apart from a record taken back, so what each
//     upload on a page changed is counted from them: 0.13 s against 0.40 s for
//     a page holding a build's first upload, which opened 379,136 findings.
//
// Widened rather than made beside them, because a second index leading with
// the build is one the planners weigh for every read of a build: SQLite took
// one ordered for the trend's grouping for the findings list's, and reached
// decided occurrences through it rather than by their identity.
func findingV0140(t *columnTypes) []string {
	statements := withIndex(findingV0110(t), "finding_group_idx",
		`CREATE INDEX "finding_group_idx" ON "finding" ("build_id", "closed_at", "visibility", "kind", "vulnerability_id", "component_id", "urgency", "urgency_exploited", "urgency_incident", "opened_at", "closed_because", "assigned_to", "opened_run_id")`)
	statements = withIndex(statements, "finding_opened_run_idx",
		`CREATE INDEX "finding_opened_run_idx" ON "finding" ("build_id", "opened_run_id", "vulnerability_id", "component_id", "visibility", "kind", "closed_run_id", "closed_because")`)
	return withIndex(statements, "finding_closed_run_idx",
		`CREATE INDEX "finding_closed_run_idx" ON "finding" ("build_id", "closed_run_id", "vulnerability_id", "component_id", "visibility", "kind", "opened_run_id", "closed_because")`)
}

// findingIndexesV0140 makes the three widened indexes again.
func findingIndexesV0140(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	return u.index(findingV0140(u.t), "finding", "finding_group_idx", "finding_opened_run_idx", "finding_closed_run_idx")
}
