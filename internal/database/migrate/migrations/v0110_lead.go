// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// leadV0110 is v0.11.0's declaration of what brings a lead out of the
// baseline and into the queue.
func leadV0110(t *columnTypes) []string {
	return []string{
		// A lead somebody pulled into the queue, by its place in a product.
		// It holds on every build the lead is on.
		`CREATE TABLE "lead_escalation" (
			"id"             ` + t.id + `,
			"product_id"     ` + t.ref + ` NOT NULL,
			"place_identity" ` + t.hash + ` NOT NULL,
			"escalated_by"   ` + t.ref + ` NOT NULL,
			"escalated_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "lead_escalation_place_unique" UNIQUE ("product_id", "place_identity"),
			CONSTRAINT "lead_escalation_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "lead_escalation_by_fk" FOREIGN KEY ("escalated_by") REFERENCES "person"("id")
		)` + t.suffix,

		// A path prefix whose baseline leads are in the queue.
		`CREATE TABLE "lead_important_path" (
			"id"              ` + t.id + `,
			"product_id"      ` + t.ref + ` NOT NULL,
			-- From the top of the checkout, with no leading or trailing slash.
			"prefix"          ` + t.free + ` NOT NULL,
			"prefix_identity" ` + t.hash + ` NOT NULL,
			-- The prefix and a slash, and its length in characters: a path
			-- under the prefix begins with it. Compared with SUBSTR, because
			-- SQLite's LIKE ignores the case of ASCII letters and a path does
			-- not, and LENGTH counts bytes on MySQL.
			"under"           ` + t.free + ` NOT NULL,
			"under_length"    INTEGER NOT NULL,
			CONSTRAINT "lead_important_path_unique" UNIQUE ("product_id", "prefix_identity"),
			CONSTRAINT "lead_important_path_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id")
		)` + t.suffix,

		// A standing rule dismissing every lead of an analyzer rule, every
		// lead under a path, or both. It covers nothing until somebody other
		// than its author approves it, and its words never change: a rule
		// worded differently is retired and proposed again.
		`CREATE TABLE "lead_rule" (
			"id"                ` + t.id + `,
			"product_id"        ` + t.ref + ` NOT NULL,
			-- The analyzer rule, as <tool>/<rule>, and folded as a rule's
			-- issue is. Null where the rule names a path alone.
			"rule"              ` + t.name + `,
			"rule_folded"       ` + t.name + `,
			-- Null where the rule names an analyzer rule alone. Held and
			-- compared as an important path is.
			"prefix"            ` + t.free + `,
			"under"             ` + t.free + `,
			"under_length"      INTEGER,
			"reason"            ` + t.kind + ` NOT NULL,
			"reasoning"         ` + t.text + ` NOT NULL,
			"proposed_by"       ` + t.ref + ` NOT NULL,
			"proposed_at"       ` + t.timestamp + ` NOT NULL,
			"approved_by"       ` + t.refNull + `,
			"approved_at"       ` + t.timestamp + `,
			-- The leads it covered when approved, which is what the approver
			-- read.
			"approved_covering" INTEGER,
			"retired_by"        ` + t.refNull + `,
			"retired_at"        ` + t.timestamp + `,
			CONSTRAINT "lead_rule_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "lead_rule_proposed_by_fk" FOREIGN KEY ("proposed_by") REFERENCES "person"("id"),
			CONSTRAINT "lead_rule_approved_by_fk" FOREIGN KEY ("approved_by") REFERENCES "person"("id"),
			CONSTRAINT "lead_rule_retired_by_fk" FOREIGN KEY ("retired_by") REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "lead_rule_product_idx" ON "lead_rule" ("product_id")`,

		// How likely a rule's results are to be real: the analyzer's own
		// rating, as the newest run rating the rule gave it, and the rank of
		// the weaknesses it names.
		`CREATE TABLE "rule_rating" (
			"id"                ` + t.id + `,
			"vulnerability_id"  ` + t.ref + ` NOT NULL,
			-- The security severity, from 0 to 10, in tenths. Null where
			-- the tool gives none.
			"severity_tenths"   INTEGER,
			-- very-high, high, medium or low. Null where the tool gives
			-- none.
			"precision"         ` + t.kind + `,
			-- How likely the weaknesses the rule names are to be a flaw
			-- worth fixing first, from 0 up, as the server's table ranks
			-- them when the rule was last recorded.
			"weakness_tier"     INTEGER NOT NULL,
			CONSTRAINT "rule_rating_rule_unique" UNIQUE ("vulnerability_id"),
			CONSTRAINT "rule_rating_rule_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id")
		)` + t.suffix,
	}
}

// createLeadV0110 makes the escalation, standing rule and rule rating tables, stepped over where they are
// already there.
func createLeadV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, table := range []string{"lead_escalation", "lead_important_path", "lead_rule", "rule_rating"} {
		present, err := u.hasColumn(table, "id")
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.create(leadV0110(u.t), table); err != nil {
			return err
		}
	}
	return nil
}
