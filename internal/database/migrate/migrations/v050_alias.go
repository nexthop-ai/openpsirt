// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// aliasV050 is v0.5.0's declaration of the names an issue answers to, and its
// index.
//
// v0.2.0's, which v0.3.0 and v0.4.0 left as it was, with whether a person typed
// the name.
func aliasV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "vulnerability_alias" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"identifier"       ` + t.name + ` NOT NULL,
			-- Folded, for the reason the issue's own identifier is.
			"identifier_folded" ` + t.name + ` NOT NULL,
			-- Whether a person typed this name rather than a scan reporting
			-- it. Only a typed name may be removed: the next scan reporting
			-- one it did not type records it again.
			"by_hand"          ` + t.boolean + ` DEFAULT FALSE NOT NULL,
			CONSTRAINT "vulnerability_alias_unique" UNIQUE ("identifier"),
			CONSTRAINT "vulnerability_alias_vulnerability_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id")
		)` + t.suffix,

		`CREATE INDEX "vulnerability_alias_folded_idx"
			ON "vulnerability_alias" ("identifier_folded", "vulnerability_id")`,
	}
}
