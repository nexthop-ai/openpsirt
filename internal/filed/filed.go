// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package filed holds the one spelling of "filed under an issue read as this
// one", for every package that relates a record to an issue.
//
// A record is filed under the issue it was made against, and that issue may
// since have merged into another. Every issue states the issue it is read as,
// so a record belongs to an issue where the two rows state the same one.
package filed

// Under is the condition that a row whose issue is held in column is about the
// issue bound in its one placeholder: filed under an issue read as the same
// one. The issue bound may itself be one that merged into another.
//
// The column is spliced into the statement, so it is always one a caller
// names in code.
func Under(column string) string {
	return column + ` IN (SELECT "mv"."id" FROM "vulnerability" AS "mv"` +
		` JOIN "vulnerability" AS "mi" ON "mi"."issue_id" = "mv"."issue_id" WHERE "mi"."id" = ?)`
}

// UnderAny is Under for a list of issues bound in its one placeholder.
func UnderAny(column string) string {
	return column + ` IN (SELECT "mv"."id" FROM "vulnerability" AS "mv"` +
		` JOIN "vulnerability" AS "mi" ON "mi"."issue_id" = "mv"."issue_id" WHERE "mi"."id" IN (?))`
}
