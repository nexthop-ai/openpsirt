// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"strings"
)

// findingV070 is v0.7.0's declaration of the finding table, and the indexes it
// makes.
//
// v0.3.0's, with the CVE record lines that closed a finding as unaffected, the
// supplier's statement that answers it, and the build's claim about it.
// Derived from v0.3.0's declaration, which a tagged release fixed and which
// never changes again.
func findingV070(t *columnTypes) []string {
	statements := findingV030(t)
	statements[0] = withColumn(statements[0], `"rated_at"         `+t.timestamp+` NULL,`,
		`-- The lines of the CVE record that state this finding's version
			-- is unaffected, as JSON, where that is why it closed. Kept on
			-- the row because the snapshot the run read is replaced by the
			-- next, and the closure has to stay explicable after it is.
			"unaffected_by"    `+t.text+` NULL,`)
	statements[0] = withColumn(statements[0], `"unaffected_by"    `+t.text+` NULL,`,
		`-- The supplier's statement that answers this finding, where one
			-- does: on a row closed as disclaimed, the statement that closed
			-- it; on an open row, a statement answering it on some routes up
			-- the tree and not on others. A plain reference without a foreign
			-- key: a statement is superseded and never deleted, so the
			-- reference cannot dangle, and a column taking a null and holding
			-- one is added where the table stands on every engine.
			"stated_by"        `+t.refNull+` NULL,`)
	statements[0] = withColumn(statements[0], `"stated_by"        `+t.refNull+` NULL,`,
		`-- The build's claim covering this finding, whatever it says. The
			-- reference above it names only a claim that suppresses; this one
			-- names a claim that the flaw applies as well, which is what
			-- carries the workaround the build published. A plain reference
			-- without a foreign key, for the reason the one above it gives.
			"claimed_by"       `+t.refNull+` NULL,`)
	return statements
}

// scanRunV070 is v0.7.0's declaration of the scan run table.
//
// v0.2.0's, with the CVE record snapshot the run read.
func scanRunV070(t *columnTypes) []string {
	for _, statement := range findingStatements(t) {
		if !strings.Contains(statement, `CREATE TABLE "scan_run"`) {
			continue
		}
		return []string{withColumn(statement, `"caution"          `+t.text+` NULL,`,
			`-- Which CVE record snapshot the run read, as the moment the
			-- snapshot describes. Null where it read none, which narrows
			-- nothing.
			"records_version"  `+t.free+` NULL,`)}
	}
	return nil
}

// withColumn adds a column to a table's declaration, after the column it
// follows.
func withColumn(statement, after, column string) string {
	at := strings.Index(statement, after)
	if at < 0 {
		panic("the declaration being extended has no column " + after)
	}
	at += len(after)
	return statement[:at] + "\n\t\t\t" + column + statement[at:]
}
