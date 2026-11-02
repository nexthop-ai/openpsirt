// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// findingV0110 is v0.11.0's declaration of the finding table, and the indexes
// it makes.
//
// v0.10.0's, renamed, with the finding's kind in each index a read answers
// from without the table. Every read of findings names the kinds it includes,
// so a covering index without the kind costs a table row per finding read.
// Derived from v0.10.0's declaration, which v0.10.0's record of its schema
// holds. The occurrence index carries the build, the kind and the row after
// the occurrence and issue, so the rows of one build after a given row at an
// occurrence are one range of it, however many builds hold the occurrence.
func findingV0110(t *columnTypes) []string {
	statements := findingV0100(t)
	statements = withIndex(statements, "finding_group_idx",
		`CREATE INDEX "finding_group_idx" ON "finding" ("target_id", "closed_at", "visibility", "kind", "vulnerability_id", "component_id", "urgency", "urgency_exploited", "urgency_exploited_here", "opened_at", "closed_because", "assigned_to")`)
	statements = withIndex(statements, "finding_opened_run_idx",
		`CREATE INDEX "finding_opened_run_idx" ON "finding" ("target_id", "opened_run_id", "vulnerability_id", "component_id", "visibility", "kind", "closed_run_id")`)
	statements = withIndex(statements, "finding_closed_run_idx",
		`CREATE INDEX "finding_closed_run_idx" ON "finding" ("target_id", "closed_run_id", "vulnerability_id", "component_id", "visibility", "kind", "opened_run_id")`)
	statements = withIndex(statements, "finding_place_idx",
		`CREATE INDEX "finding_place_idx" ON "finding" ("place_identity", "vulnerability_id", "target_id", "kind", "id")`)
	return renamedV0110(statements)
}
