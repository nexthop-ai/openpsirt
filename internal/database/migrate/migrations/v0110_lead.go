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
	}
}

// createLeadV0110 makes the escalation tables, stepped over where they are
// already there.
func createLeadV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, table := range []string{"lead_escalation", "lead_important_path"} {
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
