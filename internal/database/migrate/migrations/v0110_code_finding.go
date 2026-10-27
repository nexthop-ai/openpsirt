// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// codeFindingV0110 is v0.11.0's declaration of what a code finding's triage keeps beside it:
// suppression rules, analyzer rule ratings and families, flaw records, the
// components a flaw record confirmed, and collaborators.
func codeFindingV0110(t *columnTypes) []string {
	return []string{
		// A suppression rule dismissing every code finding of an analyzer rule, every
		// code finding under a path, or both. It covers nothing until somebody other
		// than its author approves it, and its words never change: a rule
		// worded differently is retired and proposed again.
		`CREATE TABLE "suppression_rule" (
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
			-- The code findings it covered when approved, which is what the approver
			-- read.
			"approved_covering" INTEGER,
			"retired_by"        ` + t.refNull + `,
			"retired_at"        ` + t.timestamp + `,
			CONSTRAINT "suppression_rule_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "suppression_rule_proposed_by_fk" FOREIGN KEY ("proposed_by") REFERENCES "person"("id"),
			CONSTRAINT "suppression_rule_approved_by_fk" FOREIGN KEY ("approved_by") REFERENCES "person"("id"),
			CONSTRAINT "suppression_rule_retired_by_fk" FOREIGN KEY ("retired_by") REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "suppression_rule_product_idx" ON "suppression_rule" ("product_id")`,

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
		// analyzers' code findings at one place are the same flaw, and the analyzer
		// the rule is of.
		`CREATE TABLE "rule_family" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"family"           ` + t.name + ` NOT NULL,
			-- The part of the rule's name before its first slash, in lower
			-- case: two code findings are one flaw only where two analyzers report
			-- them.
			"tool"             ` + t.name + ` NOT NULL,
			CONSTRAINT "rule_family_unique" UNIQUE ("vulnerability_id", "family"),
			CONSTRAINT "rule_family_rule_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id")
		)` + t.suffix,

		// A confirmed code finding recorded as a flaw, by its occurrence in a product.
		`CREATE TABLE "code_finding_flaw" (
			"id"                  ` + t.id + `,
			"product_id"          ` + t.ref + ` NOT NULL,
			"occurrence_identity" ` + t.hash + ` NOT NULL,
			-- The flaw it was recorded as.
			"vulnerability_id"    ` + t.ref + ` NOT NULL,
			-- The visibility the code finding's findings hold: internal while its
			-- flaw is undisclosed, and public once a code finding included in
			-- disclosure is disclosed with its flaw. A sighting opening later
			-- opens at it.
			"visibility"          ` + t.kind + ` NOT NULL,
			"recorded_by"         ` + t.ref + ` NOT NULL,
			"recorded_at"         ` + t.timestamp + ` NOT NULL,
			-- Who included it in its flaw's disclosure and when. Null while it is
			-- internal only.
			"included_by"         ` + t.refNull + `,
			"included_at"         ` + t.timestamp + `,
			-- When its flaw was disclosed, whether or not the code finding was
			-- included. Null while the flaw is undisclosed.
			"disclosed_at"        ` + t.timestamp + `,
			-- The last analysis run to describe the code finding, written before
			-- the run writes anything about it. A disclosure or an inclusion that
			-- read the flaw record before the run and writes it after finds the
			-- value changed, and reads again.
			"last_run_id"         ` + t.refNull + `,
			CONSTRAINT "code_finding_flaw_occurrence_unique" UNIQUE ("product_id", "occurrence_identity"),
			CONSTRAINT "code_finding_flaw_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "code_finding_flaw_flaw_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "code_finding_flaw_by_fk" FOREIGN KEY ("recorded_by") REFERENCES "person"("id"),
			CONSTRAINT "code_finding_flaw_included_by_fk" FOREIGN KEY ("included_by") REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "code_finding_flaw_flaw_idx" ON "code_finding_flaw" ("vulnerability_id")`,

		// The code finding a flaw was recorded from, with what its flaw record was
		// offered: it stays with the flaw after the flaw record is undone, which is
		// when the link above goes.
		`CREATE TABLE "flaw_code_finding" (
			"id"                  ` + t.id + `,
			"product_id"          ` + t.ref + ` NOT NULL,
			"vulnerability_id"    ` + t.ref + ` NOT NULL,
			-- The place of the code finding the flaw record was made at.
			"occurrence_identity" ` + t.hash + ` NOT NULL,
			-- The component the offer ranked first, which the person may
			-- have turned down. Null where it was the build itself.
			"suggested_component" ` + t.free + ` NULL,
			"suggested_ecosystem" ` + t.name + ` NULL,
			"suggested_namespace" ` + t.free + ` NULL,
			"suggested_from"      ` + t.kind + ` NOT NULL,
			"recorded_by"         ` + t.ref + ` NOT NULL,
			"recorded_at"         ` + t.timestamp + ` NOT NULL,
			-- Who undid the flaw record, when and why. Null while it stands.
			"undone_by"           ` + t.refNull + `,
			"undone_at"           ` + t.timestamp + ` NULL,
			"undone_note"         ` + t.text + ` NULL,
			CONSTRAINT "flaw_code_finding_flaw_unique" UNIQUE ("vulnerability_id"),
			CONSTRAINT "flaw_code_finding_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "flaw_code_finding_flaw_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "flaw_code_finding_by_fk" FOREIGN KEY ("recorded_by") REFERENCES "person"("id"),
			CONSTRAINT "flaw_code_finding_undone_by_fk" FOREIGN KEY ("undone_by") REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "flaw_code_finding_occurrence_idx" ON "flaw_code_finding" ("product_id", "occurrence_identity")`,

		// One build of the set a flaw record proposed the flaw against.
		`CREATE TABLE "flaw_code_finding_build" (
			"id"                   ` + t.id + `,
			"flaw_code_finding_id" ` + t.ref + ` NOT NULL,
			"build_id"            ` + t.ref + ` NOT NULL,
			-- True where the code finding was seen in it, false where it holds the
			-- chosen component and the code finding's series never analyzed it.
			"seen"                 ` + t.boolean + ` NOT NULL,
			CONSTRAINT "flaw_code_finding_build_unique" UNIQUE ("flaw_code_finding_id", "build_id"),
			CONSTRAINT "flaw_code_finding_build_code_finding_fk" FOREIGN KEY ("flaw_code_finding_id") REFERENCES "flaw_code_finding"("id"),
			CONSTRAINT "flaw_code_finding_build_build_fk" FOREIGN KEY ("build_id") REFERENCES "build"("id")
		)` + t.suffix,

		// The component a path prefix was confirmed as at a flaw record, which
		// the next flaw record under it is offered first.
		`CREATE TABLE "code_finding_component" (
			"id"              ` + t.id + `,
			"product_id"      ` + t.ref + ` NOT NULL,
			-- Held and compared as a suppression rule's prefix is.
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
			CONSTRAINT "code_finding_component_prefix_unique" UNIQUE ("product_id", "prefix_identity"),
			CONSTRAINT "code_finding_component_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "code_finding_component_by_fk" FOREIGN KEY ("confirmed_by") REFERENCES "person"("id")
		)` + t.suffix,

		// One person granted one code finding recorded as a flaw in one product, as a case
		// collaborator is granted one issue.
		`CREATE TABLE "code_finding_collaborator" (
			"id"                  ` + t.id + `,
			"product_id"          ` + t.ref + ` NOT NULL,
			"occurrence_identity" ` + t.hash + ` NOT NULL,
			"person_id"           ` + t.ref + ` NOT NULL,
			"added_by"            ` + t.ref + ` NOT NULL,
			"added_at"            ` + t.timestamp + ` NOT NULL,
			"removed_by"          ` + t.refNull + `,
			"removed_at"          ` + t.timestamp + `,
			-- The person again while the grant stands, null once it is
			-- withdrawn: one live grant per person per code finding.
			"live_person_id"      ` + t.refNull + `,
			CONSTRAINT "code_finding_collaborator_live_unique" UNIQUE ("product_id", "occurrence_identity", "live_person_id"),
			CONSTRAINT "code_finding_collaborator_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "code_finding_collaborator_person_fk" FOREIGN KEY ("person_id") REFERENCES "person"("id"),
			CONSTRAINT "code_finding_collaborator_added_by_fk" FOREIGN KEY ("added_by") REFERENCES "person"("id"),
			CONSTRAINT "code_finding_collaborator_reincluded_by_fk" FOREIGN KEY ("removed_by") REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "code_finding_collaborator_person_idx" ON "code_finding_collaborator" ("person_id")`,
	}
}

// createCodeFindingV0110 makes the suppression rule, rule rating, rule family,
// flaw record, component and collaborator tables, stepped over where they are
// already there.
func createCodeFindingV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, table := range []string{"suppression_rule", "rule_rating", "rule_family",
		"code_finding_flaw", "flaw_code_finding", "flaw_code_finding_build", "code_finding_component", "code_finding_collaborator"} {
		present, err := u.hasColumn(table, "id")
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.create(codeFindingV0110(u.t), table); err != nil {
			return err
		}
	}
	return nil
}
