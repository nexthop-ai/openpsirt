// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import "fmt"

// findingV080 is v0.8.0's declaration of the finding table, and the indexes it
// makes.
//
// v0.7.0's, with two indexes wider. Derived from v0.7.0's declaration, which
// v0.7.0's record of its schema holds.
func findingV080(t *columnTypes) []string {
	statements := findingV070(t)

	// What is open in a build, with its deadline. The deadline report for one
	// build reads the deadline as a range at the end of this prefix, so the
	// rows of other builds and outside the window are never fetched. Measured
	// on PostgreSQL with one processor, a build of 183,788 open findings in a
	// deployment of 367,577: 256 ms a page through the deployment-wide
	// deadline index, 205 ms through this one.
	statements = withIndex(statements, "finding_open_idx",
		`CREATE INDEX "finding_open_idx" ON "finding" ("target_id", "closed_at", "due_at")`)

	// The grouping columns, and then when each finding opened and why it
	// closed. The backlog trend reads only those beside the issue and the
	// build, so it is answered from the index without the table. Measured on
	// PostgreSQL with one processor over 375,843 findings: 578 pages read
	// against 16,500, the trend grouped in the database 172 ms against 88 ms,
	// and the index 4.2 MB against 4.6 MB.
	statements = withIndex(statements, "finding_group_idx",
		`CREATE INDEX "finding_group_idx" ON "finding" ("target_id", "closed_at", "visibility", "vulnerability_id", "component_id", "urgency", "urgency_exploited", "urgency_exploited_here", "opened_at", "closed_because")`)
	return statements
}

// decisionV080 is v0.8.0's declaration of the decision table, and the indexes
// it makes.
//
// The baseline's, with two indexes leading with a decision's state. Derived
// from the baseline's declaration, which v0.5.0's record of its schema holds.
func decisionV080(t *columnTypes) []string {
	made, indexes, err := pick(triageBaseline(t), "decision")
	if err != nil {
		panic(err)
	}
	statements := append([]string{made}, indexes...)
	return append(statements,
		// The decisions waiting for a second person, by claim. The review
		// queue groups the waiting decisions by claim, and the waiting ones
		// are a fraction of a table holding every decision ever made. Measured
		// on PostgreSQL with one processor, 33,150 waiting among 133,549: the
		// queue's page 81 ms against 22 ms, and its count 40 ms against 22 ms.
		`CREATE INDEX "decision_state_claim_idx" ON "decision" ("state", "claim_id")`,
		// The decisions in one state in one product, which is how the
		// decisions that stopped applying are found: 21 ms against 11 ms.
		`CREATE INDEX "decision_state_product_idx" ON "decision" ("state", "product_id")`,
	)
}

// withIndex replaces the statement creating the named index.
func withIndex(statements []string, name, stmt string) []string {
	for i, each := range statements {
		if m := createsIndex.FindStringSubmatch(each); m != nil && m[1] == name {
			out := append([]string(nil), statements...)
			out[i] = stmt
			return out
		}
	}
	panic(fmt.Sprintf("the declaration being changed makes no index %s", name))
}
