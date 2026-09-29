// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// v0.5.0's declaration of the vulnerability table.
//
// It is v0.2.0's, which v0.3.0 and v0.4.0 did not change, with the issue each
// row is read as and the day the known-exploited catalog listed it.
func vulnerabilityV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "vulnerability" (
			"id"            ` + t.id + `,
			"identifier"    ` + t.free + ` NOT NULL,
			-- The same name folded, so anything matching an issue by name
			-- compares two columns rather than a function of one. Unique,
			-- which is what keeps one name one row.
			"identifier_folded" ` + t.name + ` NOT NULL,
			-- What the world says. What we say instead belongs to one
			-- product and lives in "issue_rating".
			"severity"      ` + t.kind + ` NULL,
			"description"     ` + t.text + ` NULL,
			"advisory"        ` + t.free + ` NULL,
			"exploited"       ` + t.boolean + ` NOT NULL,
			-- The earliest day any report says the known-exploited catalog
			-- listed it. An exploited deadline counts from it, and it only
			-- ever moves earlier.
			"exploited_on"    ` + t.date + ` NULL,
			-- Held as parts per million rather than as a fraction. Every engine
			-- spells an exact decimal differently and a float compares
			-- differently again, and this has to sort in an index.
			"likelihood_ppm"  ` + t.ref + ` NULL,
			"likelihood_percentile_ppm" ` + t.ref + ` NULL,
			"likelihood_on"   ` + t.date + ` NULL,
			"score_centi"     ` + t.ref + ` NULL,
			"vector"          ` + t.free + ` NULL,
			"score_version"   ` + t.free + ` NULL,
			"score_source"    ` + t.free + ` NULL,
			"score_kind"      ` + t.free + ` NULL,
			"first_seen_at" ` + t.timestamp + ` NOT NULL,
			-- The issue this row is read as: its own identifier, or the
			-- issue it was merged into. Always the issue that stands rather
			-- than a chain, so a row merged twice is one step from the issue
			-- that holds its findings.
			--
			-- Its own identifier rather than a null for a row nothing merged:
			-- a triage record is related to a finding through this column by
			-- equality, which every engine answers from an index. Written
			-- with a null or a function of two columns, the relation became a
			-- filter over every decision in a product, and a count over a
			-- full-size build ran for more than ten minutes on PostgreSQL.
			--
			-- No foreign key: a row is written before its identifier is
			-- known, and the merge record below carries both identifiers
			-- under keys of its own.
			"issue_id"      ` + t.ref + ` NOT NULL,
			CONSTRAINT "vulnerability_folded_unique" UNIQUE ("identifier_folded")
		)` + t.suffix,

		// Every row read as one issue, from the finding's side of the
		// relation: a finding holds the issue, and the rows filed under it
		// are asked for by this column.
		`CREATE INDEX "vulnerability_issue_idx" ON "vulnerability" ("issue_id", "id")`,
	}
}

// v0.5.0's declaration of the record of one issue merged into another, and of
// a decision a merge superseded.
func mergeV050(t *columnTypes) []string {
	return []string{
		// One issue merged into another, because a report named both.
		//
		// The act is a record of its own. Everything filed under the issue
		// that was absorbed — decisions, their approvals, notes, ratings —
		// stays filed under it, and is read as the issue it merged into
		// through the column above.
		`CREATE TABLE "vulnerability_merge" (
			"id"          ` + t.id + `,
			-- Once only: an issue merged into another holds no findings and
			-- no aliases after, and every lookup by the name it keeps
			-- resolves through the issue it states, so no later report
			-- merges it again.
			"absorbed_id" ` + t.ref + ` NOT NULL,
			-- The issue it was merged into at the time. A later merge of
			-- that issue is a record of its own.
			"kept_id"     ` + t.ref + ` NOT NULL,
			-- The names the report gave the issue, as it gave them.
			"named"       ` + t.free + ` NOT NULL,
			-- The run whose report named both, where a scan was what did.
			"run_id"      ` + t.refNull + ` NULL,
			"merged_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "vulnerability_merge_once" UNIQUE ("absorbed_id"),
			CONSTRAINT "vulnerability_merge_absorbed_fk" FOREIGN KEY ("absorbed_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "vulnerability_merge_kept_fk" FOREIGN KEY ("kept_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "vulnerability_merge_run_fk" FOREIGN KEY ("run_id")
				REFERENCES "scan_run"("id")
		)` + t.suffix,

		// What one issue's merges are read by.
		`CREATE INDEX "vulnerability_merge_kept_idx" ON "vulnerability_merge" ("kept_id")`,

		// A live decision that stopped standing because a merge put another
		// live decision at the same place.
		//
		// The decision itself lapses the way any decision does. This is why:
		// which merge did it, and which decision stands in its place.
		`CREATE TABLE "decision_superseded" (
			"id"          ` + t.id + `,
			"decision_id" ` + t.ref + ` NOT NULL,
			"standing_id" ` + t.ref + ` NOT NULL,
			"merge_id"    ` + t.ref + ` NOT NULL,
			-- Whether the two said different things. Only a disagreement is
			-- told to anybody: two decisions saying the same thing collapse
			-- to one and nothing about the place changes.
			"disagreed"   ` + t.boolean + ` NOT NULL,
			CONSTRAINT "decision_superseded_once" UNIQUE ("decision_id"),
			CONSTRAINT "decision_superseded_decision_fk" FOREIGN KEY ("decision_id")
				REFERENCES "decision"("id"),
			CONSTRAINT "decision_superseded_standing_fk" FOREIGN KEY ("standing_id")
				REFERENCES "decision"("id"),
			CONSTRAINT "decision_superseded_merge_fk" FOREIGN KEY ("merge_id")
				REFERENCES "vulnerability_merge"("id")
		)` + t.suffix,
	}
}

// v0.5.0's declaration of the assessment table.
//
// It is v0.1.0's, which no release since changed, with the reason a claim
// was withdrawn where no person withdrew it.
func assessmentV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "assessment" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The product this is a rating for. Recording, agreeing to and
			-- withdrawing one all ask for triage on this product, so the
			-- column is what the authorization is asked about rather than a
			-- label beside it.
			"product_id"       ` + t.ref + ` NOT NULL,
			"severity"         ` + t.kind + ` NOT NULL,
			-- What was published when this was made, kept so a later reader
			-- can see what we were disagreeing with rather than having to
			-- infer it from a feed that has since moved on.
			"published"     ` + t.kind + ` NULL,
			"reasoning"     ` + t.text + ` NOT NULL,
			"state"         ` + t.kind + ` NOT NULL,
			"needs_approval" ` + t.boolean + ` NOT NULL,
			"proposed_by"   ` + t.ref + ` NOT NULL,
			"proposed_at"   ` + t.timestamp + ` NOT NULL,
			"decided_by"    ` + t.refNull + ` NULL,
			"decided_at"    ` + t.timestamp + ` NULL,
			-- Why a claim was withdrawn where no person withdrew it: a merge
			-- of two issues that left another claim standing in the product.
			-- Null for a claim a person withdrew, which "decided_by" names.
			"withdrawn_because" ` + t.text + ` NULL,
			-- The issue this is a claim about, while it is still a live claim:
			-- the same value as "vulnerability_id" until the claim is
			-- withdrawn, and null after. Paired with the product under a
			-- unique constraint that is how "one live claim per issue and
			-- product" is enforced by the database rather than by a check —
			-- null values do not collide in a unique index on any of the four
			-- engines, so any number of withdrawn claims may sit beside the
			-- live one, and two proposals arriving at once cannot both get
			-- through. A read-then-write check is exactly the shape both of
			-- them walk through.
			--
			-- The product is repeated in the pair rather than the constraint
			-- reading "product_id" itself, because the nulls are what release
			-- a withdrawn claim and "product_id" is never null.
			--
			-- No foreign key of its own: "vulnerability_id" already carries
			-- one, and this column is the mechanism that holds the rule
			-- rather than a second reference to the issue.
			"live_vulnerability_id" ` + t.refNull + ` NULL,
			CONSTRAINT "assessment_live_unique" UNIQUE ("live_vulnerability_id", "product_id"),
			CONSTRAINT "assessment_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "assessment_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "assessment_proposer_fk" FOREIGN KEY ("proposed_by")
				REFERENCES "person"("id"),
			CONSTRAINT "assessment_decider_fk" FOREIGN KEY ("decided_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// Reading an issue's claims in a product, live and withdrawn alike.
		// What holds the rule that only one of them is live is the unique
		// constraint above, not this.
		`CREATE INDEX "assessment_issue_idx" ON "assessment" ("vulnerability_id", "product_id", "state")`,
		`CREATE INDEX "assessment_waiting_idx" ON "assessment" ("state", "needs_approval")`,
	}
}
