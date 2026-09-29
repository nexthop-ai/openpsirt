// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// advisoryV050 is v0.5.0's declaration of a release an advisory marks
// affected, and of what an agreement to an advisory saw about each release.
//
// Both are new in v0.5.0, which states a release covered by approved
// decisions that the flaw does not apply as known not affected.
func advisoryV050(t *columnTypes) []string {
	return []string{
		// A release the person preparing an advisory marks affected whatever
		// its decisions say. Part of what the advisory says, so setting one
		// and clearing one each open an edition.
		`CREATE TABLE "advisory_override" (
			"id"               ` + t.id + `,
			"advisory_id"      ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The release, as the stream and the variant it was built from.
			"stream_id"        ` + t.ref + ` NOT NULL,
			"variant_id"       ` + t.ref + ` NOT NULL,
			"set_at"           ` + t.timestamp + ` NOT NULL,
			"set_by"           ` + t.ref + ` NOT NULL,
			-- Cleared, by whom. The row stays so that the act has somewhere to
			-- be written, and marking the release again revives it, which is
			-- what keeps the release marked once.
			"removed_at"       ` + t.timestamp + ` NULL,
			"removed_by"       ` + t.refNull + ` NULL,
			CONSTRAINT "advisory_override_once" UNIQUE
				("advisory_id", "product_id", "vulnerability_id", "stream_id", "variant_id"),
			CONSTRAINT "advisory_override_advisory_fk"
				FOREIGN KEY ("advisory_id") REFERENCES "advisory"("id"),
			CONSTRAINT "advisory_override_product_fk"
				FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "advisory_override_vulnerability_fk"
				FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "advisory_override_stream_fk"
				FOREIGN KEY ("stream_id") REFERENCES "stream"("id"),
			CONSTRAINT "advisory_override_variant_fk"
				FOREIGN KEY ("variant_id") REFERENCES "variant"("id"),
			CONSTRAINT "advisory_override_by_fk"
				FOREIGN KEY ("set_by") REFERENCES "person"("id"),
			CONSTRAINT "advisory_override_back_fk"
				FOREIGN KEY ("removed_by") REFERENCES "person"("id")
		)` + t.suffix,

		// What each release stood at when a second person agreed to the
		// advisory. A fact about a moment: a decision approved or lapsing
		// afterwards moves a release's status without withdrawing the
		// agreement, and this is what says it moved since.
		`CREATE TABLE "advisory_agreed_status" (
			"id"               ` + t.id + `,
			"approval_id"      ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"stream_id"        ` + t.ref + ` NOT NULL,
			"variant_id"       ` + t.ref + ` NOT NULL,
			-- The standard's word for it: known_affected, known_not_affected
			-- or fixed.
			"status"           ` + t.name + ` NOT NULL,
			CONSTRAINT "advisory_agreed_status_approval_fk"
				FOREIGN KEY ("approval_id") REFERENCES "advisory_approval"("id"),
			CONSTRAINT "advisory_agreed_status_product_fk"
				FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "advisory_agreed_status_vulnerability_fk"
				FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "advisory_agreed_status_stream_fk"
				FOREIGN KEY ("stream_id") REFERENCES "stream"("id"),
			CONSTRAINT "advisory_agreed_status_variant_fk"
				FOREIGN KEY ("variant_id") REFERENCES "variant"("id")
		)` + t.suffix,

		// On the agreement, which is what the read asks for: the statuses
		// the agreements standing on what the advisory says now saw.
		`CREATE INDEX "advisory_agreed_status_approval_idx" ON "advisory_agreed_status" ("approval_id")`,
	}
}
