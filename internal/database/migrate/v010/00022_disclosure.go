// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package v010

import (
	"context"
	"database/sql"
)

func init() {
	register(upDisclosureExtension, downDisclosureExtension)
}

// Every time somebody moved the end of an embargo, and why.
//
// **Kept in full, never overwritten.** The date itself lives on the finding
// and says only where the embargo ends now; the question an auditor asks is
// how it got there. One extension is a judgment and six is a policy nobody
// wrote down, and the difference is invisible if each one replaces the last.
//
// Keyed on the issue in the product, which is the unit a decision uses: an
// embargo is about a vulnerability in one product's code, not about a row.
//
// **An extension that needs a second person does not move the date until it
// has one.** The row is written either way — a request that was refused, or is
// still waiting, is part of the record of how long this stayed hidden — and
// the finding's own date follows only an approved one.
func upDisclosureExtension(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "disclosure_extension" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			-- Where the embargo ended before, and where it is being asked to
			-- end. Both kept: "extended by three weeks" is not answerable from
			-- the new date alone once a second extension follows it.
			"was"              ` + t.timestamp + ` NOT NULL,
			"until"            ` + t.timestamp + ` NOT NULL,
			-- Why. Required, always, however short: an extension with no
			-- reason is the record saying somebody moved it and nothing else,
			-- which is the state this table exists to prevent.
			"reason"           ` + t.text + ` NOT NULL,
			"asked_by"         ` + t.ref + ` NOT NULL,
			"asked_at"         ` + t.timestamp + ` NOT NULL,
			-- Whether a second person had to agree. Recorded rather than
			-- recomputed: the threshold is a setting and it moves, so asking
			-- today whether a two-year-old extension needed approval would
			-- answer with today's policy.
			"needs_approval"   ` + t.boolean + ` NOT NULL,
			"approved_by"      ` + t.refNull + ` NULL,
			"approved_at"      ` + t.timestamp + ` NULL,
			CONSTRAINT "disclosure_extension_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "disclosure_extension_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "disclosure_extension_asked_by_fk" FOREIGN KEY ("asked_by") REFERENCES "person"("id"),
			CONSTRAINT "disclosure_extension_approved_by_fk" FOREIGN KEY ("approved_by") REFERENCES "person"("id")
		)` + t.suffix,

		// What this embargo has already been moved by, which is what the
		// threshold is measured against.
		`CREATE INDEX "disclosure_extension_place_idx"
			ON "disclosure_extension" ("vulnerability_id", "product_id")`,
	}

	return apply(ctx, tx, statements)
}

func downDisclosureExtension(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "disclosure_extension")
}
