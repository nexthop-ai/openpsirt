// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import "strings"

// statementTextV090 is v0.9.0's declaration of the table a claim's reasoning
// is stored in, once.
//
// A statement naming five thousand components is five thousand claim rows,
// and each gave the same reasoning. The rows point here instead of carrying a
// copy each, and two documents giving the same reasoning share one row.
func statementTextV090(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "statement_text" (
			"id"           ` + t.id + `,
			-- The digest of the words, which is what a writer finds the
			-- stored copy by. The words are longer than an index key may be
			-- on some engines.
			"words_digest" ` + t.hash + ` NOT NULL,
			-- What the statement says, cut to the bound a markdown field typed
			-- here is held to.
			"words"        ` + t.text + ` NOT NULL,
			CONSTRAINT "statement_text_digest_unique" UNIQUE ("words_digest")
		)` + t.suffix,
	}
}

// pointedAtWords replaces the column v0.7.0 declares a claim's reasoning in
// with a reference to its stored copy.
func pointedAtWords(statement, was, t string) string {
	if !strings.Contains(statement, was) {
		panic("the declaration being changed has no column " + was)
	}
	return strings.Replace(statement, was, `-- The reasoning the claim gives, stored once however many
			-- subjects its statement names. Null where it gave none. A plain
			-- reference without a foreign key: stored reasoning is never
			-- deleted, so the reference cannot dangle.
			"statement_id" `+t+` NULL,`, 1)
}

// suppressionV090 is v0.9.0's declaration of a build's own claims: v0.7.0's,
// with the reasoning stored once and pointed at.
func suppressionV090(t *columnTypes) []string {
	statements := suppressionV070(t)
	statements[0] = pointedAtWords(statements[0], `"statement"      `+t.text+` NULL,`, t.refNull)
	return statements
}

// vexStatementsV090 is v0.9.0's declaration of a supplier's statements:
// v0.7.0's, with the reasoning stored once and pointed at.
func vexStatementsV090(t *columnTypes) []string {
	statements := vexStatementsV070(t)
	statements[0] = pointedAtWords(statements[0], `"statement"   `+t.text+` NULL,`, t.refNull)
	return statements
}
