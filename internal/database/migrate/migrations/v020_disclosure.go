// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// Every time somebody moved the end of an embargo, and why.
//
// Kept in full, never overwritten. The date itself lives on the finding
// and says only where the embargo ends now; the question an auditor asks is
// how it got there. One movement is a judgment and six is a policy nobody
// wrote down, and the difference is invisible if each one replaces the last.
//
// Keyed on the issue in the product, which is the unit a decision uses: an
// embargo is about a vulnerability in one product's code, not about a row.
//
// A movement that needs a second person does not move the date until it
// has one. The row is written either way — a request that was refused, or is
// still waiting, is part of the record of how long this stayed hidden — and
// the finding's own date follows only an approved one.
func disclosureMovementStatements(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "disclosure_movement" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			-- Which act this was. Stored rather than read off the two dates:
			-- extending an embargo because a fix slipped and shortening one
			-- because it leaked are different events, and a reader working
			-- out which from the sign of a date change is reading an
			-- inference.
			"act"              ` + t.kind + ` NOT NULL,
			-- Where the embargo ended before, and where it is being asked to
			-- end. Both kept: "extended by three weeks" is not answerable from
			-- the new date alone once a second movement follows it.
			"was"              ` + t.timestamp + ` NOT NULL,
			"until"            ` + t.timestamp + ` NOT NULL,
			-- Why. Required, always, however short: a movement with no
			-- reason is the record saying somebody moved it and nothing else,
			-- which is the state this table exists to prevent.
			"reason"           ` + t.text + ` NOT NULL,
			"asked_by"         ` + t.ref + ` NOT NULL,
			"asked_at"         ` + t.timestamp + ` NOT NULL,
			-- Whether a second person had to agree. Recorded rather than
			-- recomputed: the threshold is a setting and it moves, so asking
			-- today whether a two-year-old movement needed approval would
			-- answer with today's policy.
			"needs_approval"   ` + t.boolean + ` NOT NULL,
			"approved_by"      ` + t.refNull + ` NULL,
			"approved_at"      ` + t.timestamp + ` NULL,
			CONSTRAINT "disclosure_movement_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "disclosure_movement_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "disclosure_movement_asked_by_fk" FOREIGN KEY ("asked_by") REFERENCES "person"("id"),
			CONSTRAINT "disclosure_movement_approved_by_fk" FOREIGN KEY ("approved_by") REFERENCES "person"("id")
		)` + t.suffix,

		// The distance this embargo has already been moved, which is what the
		// threshold is measured against.
		`CREATE INDEX "disclosure_movement_place_idx"
			ON "disclosure_movement" ("vulnerability_id", "product_id")`,
	}
}
