// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import "strings"

// vexStatementsV070 is v0.7.0's declaration of the vex_statement table, and the
// indexes it makes.
//
// v0.2.0's, with the product the statement's component ships inside, and when
// a later document last said it again. Derived
// from v0.2.0's declaration, which a tagged release fixed and which never
// changes again.
func vexStatementsV070(t *columnTypes) []string {
	statements := vexStatements(t)
	statements[0] = withColumn(statements[0], `"component"   `+t.name+` NOT NULL,`,
		`-- The product the component ships inside, where the document
			-- named one: the product of an OpenVEX statement with
			-- subcomponents, the platform a CSAF relationship composes the
			-- component into. A supplier speaking about its own product
			-- speaks about what sits inside it, so this is what places the
			-- statement in a build. The package identifier where the document
			-- gave one, the name, folded, and the version it was stated at.
			-- Null where the document named the component alone.
			"within_purl"  `+t.free+` NULL,
			"within"       `+t.name+` NULL,
			"within_about" `+t.name+` NULL,
			-- What the statement names its supplier's product as: inside,
			-- for a component inside a product the document named; product,
			-- for a product named alone by no package identifier. Null for a
			-- package named alone, which cannot be told from a rebuild of its
			-- source, and for every statement recorded before this was read,
			-- so that neither closes anything.
			"placement"    `+t.kind+` NULL,`)
	statements[0] = withColumn(statements[0], `"uploaded_at" `+t.timestamp+` NOT NULL,`,
		`-- When a later document from the publisher said the statement
			-- again, word for word, where one has. The row is kept for the
			-- repeat, so this is the moment the publisher last said it. Null
			-- for a statement nothing has repeated.
			"restated_at" `+t.timestamp+` NULL,`)
	return statements
}

// vexIssuanceV070 is v0.7.0's declaration of the vex_issuance table.
//
// v0.2.0's, with the kind of document that went out. Each kind is a document
// of its own, with an identifier and revisions of its own, so the revisions
// are numbered per build and kind.
func vexIssuanceV070(t *columnTypes) []string {
	statements := vexIssuanceStatements(t)
	statements[0] = withColumn(statements[0], `"target_id" `+t.ref+` NOT NULL,`,
		`-- Which document about the build went out: what this deployment
			-- agreed to, or that with what suppliers state about their own
			-- products beside it. Each is a document of its own, so a reader
			-- holding one never sees it change into the other.
			"kind"      `+t.kind+` NOT NULL,`)
	const once = `CONSTRAINT "vex_issuance_once" UNIQUE ("target_id", "ordinal")`
	if !strings.Contains(statements[0], once) {
		panic("the declaration being extended has no rule " + once)
	}
	statements[0] = strings.Replace(statements[0], once,
		`CONSTRAINT "vex_issuance_once_per_kind" UNIQUE ("target_id", "kind", "ordinal")`, 1)
	return statements
}
