// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// findingV0100 is v0.10.0's declaration of the finding table, and the indexes
// it makes.
//
// v0.9.0's, with an index on each of the two runs a finding names. Derived from
// v0.9.0's declaration, which v0.9.0's record of its schema holds.
func findingV0100(t *columnTypes) []string {
	return append(findingV090(t),
		// What a run opened, and what it closed, counted per page of receipts.
		// Each count is the distinct issues at components among a build's
		// findings naming the run, at the visibilities a reader may see,
		// leaving out a finding opened and closed by one run. Each index holds
		// every column that count reads, so it reads the rows of the runs asked
		// about and not the table. A run's own screen also reads each
		// finding's rating and exploitation, which neither index holds, so it
		// reads the table.
		// Measured on PostgreSQL over a switch image built nightly for a year,
		// 1,159,943 findings with a hundredth of its packages moving a night:
		// the page of fifty receipts took 510 ms without them, reading every
		// finding of the build, and 74 ms with them. Each index is 21 to 29 MB
		// beside a 306 MB table and takes 0.7 s to build.
		`CREATE INDEX "finding_opened_run_idx" ON "finding" ("target_id", "opened_run_id", "vulnerability_id", "component_id", "visibility", "closed_run_id")`,
		`CREATE INDEX "finding_closed_run_idx" ON "finding" ("target_id", "closed_run_id", "vulnerability_id", "component_id", "visibility", "opened_run_id")`,
	)
}
