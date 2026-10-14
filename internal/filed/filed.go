// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package filed holds the one spelling of "filed under an issue read as this
// one", for every package that relates a record to an issue.
//
// A record is filed under the issue it was made against, and that issue may
// since have merged into another. Every issue states the issue it is read as,
// so a record belongs to an issue where the two rows state the same one.
package filed

// Column is a column holding an issue, as a statement names it.
//
// A column is spliced into the statement rather than bound, so the set is
// closed and named here: a type a caller cannot build from a string it was
// handed leaves nothing between a column name from a request and the
// statement except the conversion, which shows at the call site.
type Column string

// The columns rows relate to an issue through, each by the alias its table
// takes in the statements that ask.
const (
	// Issue is the column on a statement over one table, unqualified.
	Issue Column = `"vulnerability_id"`
	// DecisionIssue is a decision's issue.
	DecisionIssue Column = `"de"."vulnerability_id"`
	// ReportIssue is the issue a flaw report stands for.
	ReportIssue Column = `"fr"."vulnerability_id"`
	// ExploitedIssue is the issue a record of exploitation here is about.
	ExploitedIssue Column = `"eh"."vulnerability_id"`
	// CaseIssue is the issue a case grant names.
	CaseIssue Column = `"cc"."vulnerability_id"`
	// AbsorbedIssue is the issue a merge folded into another.
	AbsorbedIssue Column = `"vm"."absorbed_id"`
)

// Under is the condition that a row whose issue is held in column is about the
// issue bound in its one placeholder: filed under an issue read as the same
// one. The issue bound may itself be one that merged into another.
func Under(column Column) string {
	return string(column) + ` IN (SELECT "mv"."id" FROM "vulnerability" AS "mv"` +
		` JOIN "vulnerability" AS "mi" ON "mi"."issue_id" = "mv"."issue_id" WHERE "mi"."id" = ?)`
}

// UnderAny is Under for a list of issues bound in its one placeholder.
func UnderAny(column Column) string {
	return string(column) + ` IN (SELECT "mv"."id" FROM "vulnerability" AS "mv"` +
		` JOIN "vulnerability" AS "mi" ON "mi"."issue_id" = "mv"."issue_id" WHERE "mi"."id" IN (?))`
}
