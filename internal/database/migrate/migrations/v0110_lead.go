// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// leadV0110 is v0.11.0's declaration of what a lead's triage keeps beside it:
// standing rules, analyzer rule ratings and families, hand-offs, the
// components a hand-off confirmed, and collaborators.
func leadV0110(t *columnTypes) []string {
	return []string{
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
			-- Null where the rule names an analyzer rule alone. From the top
			-- of the checkout, with no leading or trailing slash.
			"prefix"            ` + t.free + `,
			-- The prefix and a slash, and its length in characters: a path
			-- under the prefix begins with it. Compared with SUBSTR, because
			-- SQLite's LIKE ignores the case of ASCII letters and a path does
			-- not, and LENGTH counts bytes on MySQL.
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

		// The weakness families a rule's weaknesses belong to, by which two
		// analyzers' leads at one place are the same flaw, and the analyzer
		// the rule is of.
		`CREATE TABLE "rule_family" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"family"           ` + t.name + ` NOT NULL,
			-- The part of the rule's name before its first slash, in lower
			-- case: two leads are one flaw only where two analyzers report
			-- them.
			"tool"             ` + t.name + ` NOT NULL,
			CONSTRAINT "rule_family_unique" UNIQUE ("vulnerability_id", "family"),
			CONSTRAINT "rule_family_rule_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id")
		)` + t.suffix,

		// A confirmed lead recorded as a flaw, by its place in a product.
		`CREATE TABLE "lead_handoff" (
			"id"               ` + t.id + `,
			"product_id"       ` + t.ref + ` NOT NULL,
			"occurrence_identity" ` + t.hash + ` NOT NULL,
			-- The flaw it was recorded as.
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The visibility the lead's findings hold: internal while its
			-- flaw is undisclosed, kept or moved, and public once a moved
			-- lead is disclosed with its flaw. A sighting opening later
			-- opens at it.
			"visibility"       ` + t.kind + ` NOT NULL,
			"handed_by"        ` + t.ref + ` NOT NULL,
			"handed_at"        ` + t.timestamp + ` NOT NULL,
			-- Who moved it into the case and when. Null where it is kept.
			"moved_by"         ` + t.refNull + `,
			"moved_at"         ` + t.timestamp + `,
			-- When its flaw was disclosed, kept or moved. Null while the
			-- flaw is undisclosed.
			"disclosed_at"     ` + t.timestamp + `,
			-- The last analysis run to describe the lead, written before
			-- the run writes anything about it. A disclosure or a move that
			-- read the hand-off before the run and writes it after finds the
			-- value changed, and reads again.
			"last_run_id"      ` + t.refNull + `,
			CONSTRAINT "lead_handoff_occurrence_unique" UNIQUE ("product_id", "occurrence_identity"),
			CONSTRAINT "lead_handoff_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "lead_handoff_flaw_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "lead_handoff_by_fk" FOREIGN KEY ("handed_by") REFERENCES "person"("id"),
			CONSTRAINT "lead_handoff_moved_by_fk" FOREIGN KEY ("moved_by") REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "lead_handoff_flaw_idx" ON "lead_handoff" ("vulnerability_id")`,

		// The lead a flaw was recorded from, with what its hand-off was
		// offered: kept with the flaw after the hand-off is undone, which is
		// when the link above goes.
		`CREATE TABLE "flaw_lead" (
			"id"                  ` + t.id + `,
			"product_id"          ` + t.ref + ` NOT NULL,
			"vulnerability_id"    ` + t.ref + ` NOT NULL,
			-- The place of the lead the hand-off was made at.
			"occurrence_identity" ` + t.hash + ` NOT NULL,
			-- The component the offer ranked first, which the person may
			-- have turned down. Null where it was the build itself.
			"suggested_component" ` + t.free + ` NULL,
			"suggested_ecosystem" ` + t.name + ` NULL,
			"suggested_namespace" ` + t.free + ` NULL,
			"suggested_from"      ` + t.kind + ` NOT NULL,
			"handed_by"           ` + t.ref + ` NOT NULL,
			"handed_at"           ` + t.timestamp + ` NOT NULL,
			-- Who undid the hand-off, when and why. Null while it stands.
			"undone_by"           ` + t.refNull + `,
			"undone_at"           ` + t.timestamp + ` NULL,
			"undone_note"         ` + t.text + ` NULL,
			CONSTRAINT "flaw_lead_flaw_unique" UNIQUE ("vulnerability_id"),
			CONSTRAINT "flaw_lead_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "flaw_lead_flaw_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "flaw_lead_by_fk" FOREIGN KEY ("handed_by") REFERENCES "person"("id"),
			CONSTRAINT "flaw_lead_undone_by_fk" FOREIGN KEY ("undone_by") REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "flaw_lead_occurrence_idx" ON "flaw_lead" ("product_id", "occurrence_identity")`,

		// One build of the set a hand-off proposed the flaw against.
		`CREATE TABLE "flaw_lead_build" (
			"id"           ` + t.id + `,
			"flaw_lead_id" ` + t.ref + ` NOT NULL,
			"target_id"    ` + t.ref + ` NOT NULL,
			-- True where the lead was seen in it, false where it holds the
			-- chosen component and the lead's series never analyzed it.
			"seen"         ` + t.boolean + ` NOT NULL,
			CONSTRAINT "flaw_lead_build_unique" UNIQUE ("flaw_lead_id", "target_id"),
			CONSTRAINT "flaw_lead_build_lead_fk" FOREIGN KEY ("flaw_lead_id") REFERENCES "flaw_lead"("id"),
			CONSTRAINT "flaw_lead_build_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id")
		)` + t.suffix,

		// The component a path prefix was confirmed as at a hand-off, which
		// the next hand-off under it is offered first.
		`CREATE TABLE "lead_component" (
			"id"              ` + t.id + `,
			"product_id"      ` + t.ref + ` NOT NULL,
			-- Held and compared as a standing rule's prefix is.
			"prefix"          ` + t.free + ` NOT NULL,
			"prefix_identity" ` + t.hash + ` NOT NULL,
			"under"           ` + t.free + ` NOT NULL,
			"under_length"    INTEGER NOT NULL,
			-- The component as a build names it, without its version: the
			-- version moves from build to build and the prefix does not.
			"component"       ` + t.free + ` NOT NULL,
			"ecosystem"       ` + t.name + ` NULL,
			"namespace"       ` + t.free + ` NULL,
			"confirmed_by"    ` + t.ref + ` NOT NULL,
			"confirmed_at"    ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "lead_component_prefix_unique" UNIQUE ("product_id", "prefix_identity"),
			CONSTRAINT "lead_component_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "lead_component_by_fk" FOREIGN KEY ("confirmed_by") REFERENCES "person"("id")
		)` + t.suffix,

		// One person granted one handed-off lead in one product, as a case
		// collaborator is granted one issue.
		`CREATE TABLE "lead_collaborator" (
			"id"             ` + t.id + `,
			"product_id"     ` + t.ref + ` NOT NULL,
			"occurrence_identity" ` + t.hash + ` NOT NULL,
			"person_id"      ` + t.ref + ` NOT NULL,
			"added_by"       ` + t.ref + ` NOT NULL,
			"added_at"       ` + t.timestamp + ` NOT NULL,
			"removed_by"     ` + t.refNull + `,
			"removed_at"     ` + t.timestamp + `,
			-- The person again while the grant stands, null once it is
			-- withdrawn: one live grant per person per lead.
			"live_person_id" ` + t.refNull + `,
			CONSTRAINT "lead_collaborator_live_unique" UNIQUE ("product_id", "occurrence_identity", "live_person_id"),
			CONSTRAINT "lead_collaborator_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "lead_collaborator_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "lead_collaborator_added_by_fk" FOREIGN KEY ("added_by") REFERENCES "person"("id"),
			CONSTRAINT "lead_collaborator_removed_by_fk" FOREIGN KEY ("removed_by") REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "lead_collaborator_person_idx" ON "lead_collaborator" ("person_id")`,
	}
}

// createLeadV0110 makes the standing rule, rule rating, rule family,
// hand-off, component and collaborator tables, stepped over where they are
// already there.
func createLeadV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, table := range []string{"lead_rule", "rule_rating", "rule_family",
		"lead_handoff", "flaw_lead", "flaw_lead_build", "lead_component", "lead_collaborator"} {
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
