// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// disclosureMovementBaseline declares the record of every time an embargo's end
// moved: the ruling that recorded a movement, the claim its date counts from,
// and both dates, each absent where a ruling recorded it.
func disclosureMovementBaseline(t *columnTypes) []string {
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
			-- the new date alone once a second movement follows it. Only a
			-- movement a ruling recorded holds a null: an embargo it started
			-- had no end before, and one its withdrawal put back may have
			-- none after.
			"was"              ` + t.timestamp + ` NULL,
			"until"            ` + t.timestamp + ` NULL,
			-- Why. Required, always, however short: a movement with no
			-- reason is the record saying somebody moved it and nothing else,
			-- which is the state this table exists to prevent. A movement a
			-- ruling recorded carries the ruling's reasoning, which a
			-- duplicate may leave empty: its reason is the issue it names.
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
			-- The ruling on vulnerability reports that recorded this
			-- movement, and the claim whose arrival its date counts from.
			-- Null on a movement a person asked for.
			"ruling_id"        ` + t.refNull + ` NULL,
			"flaw_report_id"   ` + t.refNull + ` NULL,
			CONSTRAINT "disclosure_movement_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "disclosure_movement_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "disclosure_movement_asked_by_fk" FOREIGN KEY ("asked_by") REFERENCES "person"("id"),
			CONSTRAINT "disclosure_movement_approved_by_fk" FOREIGN KEY ("approved_by") REFERENCES "person"("id"),
			CONSTRAINT "disclosure_movement_ruling_fk" FOREIGN KEY ("ruling_id") REFERENCES "report_ruling"("id"),
			CONSTRAINT "disclosure_movement_report_fk" FOREIGN KEY ("flaw_report_id") REFERENCES "flaw_report"("id")
		)` + t.suffix,

		// The distance this embargo has already been moved, which is what the
		// threshold is measured against.
		`CREATE INDEX "disclosure_movement_place_idx"
			ON "disclosure_movement" ("vulnerability_id", "product_id")`,
	}
}

// Somebody recording that this product was attacked through an issue.
//
// The one fact about exploitation that no feed reports. A feed says a
// vulnerability is being exploited somewhere in the world; a triage outcome
// says the vulnerability applies to this product; this says that this product
// was the thing attacked. Only the third is an incident, and it arrives from a
// customer, a researcher or an investigation rather than from anything that
// can be fetched.
//
// Against the issue and one product, the shape an assessment already has. A
// place would be wrong twice over: the attack is a fact about the product
// rather than about a dependency path, and keyed to a place it would lapse
// when somebody rebuilt.
//
// Nothing verifies it, which is what makes it append-only and what makes
// clearing it an act with a name attached. A row is never edited and never
// deleted; clearing writes the moment and the person into the row that stands
// and releases the key, so the next one may be recorded.
func obligationBaseline(t *columnTypes) []string {
	return []string{

		`CREATE TABLE "exploited_here" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The product that was attacked. Recording one and clearing one
			-- both ask for triage on this product, so the column is what the
			-- authorization is asked about rather than a label beside it.
			"product_id"       ` + t.ref + ` NOT NULL,
			-- When this became known here, which is what every window a
			-- deployment might be under counts from. Supplied rather than
			-- taken from the clock: somebody learns of an attack before they
			-- reach a screen, and the gap between the two is exactly what a
			-- window measures.
			"known_at"    ` + t.timestamp + ` NOT NULL,
			-- What is being asserted. Nothing re-checks this, so the grounds
			-- are the whole of what a later reader has.
			"grounds"     ` + t.text + ` NOT NULL,
			"recorded_by" ` + t.ref + ` NOT NULL,
			"recorded_at" ` + t.timestamp + ` NOT NULL,
			-- Clearing, which is a deliberate human act and never a side
			-- effect of a scan. The reason is required with it for the reason
			-- the grounds are required above: nothing else says why the
			-- record stopped standing.
			"cleared_at"      ` + t.timestamp + ` NULL,
			"cleared_by"      ` + t.refNull + ` NULL,
			"cleared_because" ` + t.text + ` NULL,
			-- The issue this record is about while it still stands, and null
			-- once it is cleared. Paired with the product under a unique
			-- constraint, that is how "one standing record per issue and
			-- product" is enforced by the database rather than by a check —
			-- null values do not collide in a unique index on any of the four
			-- engines, so any number of cleared records sit beside the one
			-- that stands, and two arriving at once cannot both get through.
			--
			-- The product is repeated in the pair rather than the constraint
			-- reading "product_id" itself, because the nulls are what release
			-- a cleared record and "product_id" is never null.
			--
			-- No foreign key of its own: "vulnerability_id" already carries
			-- one, and this column is the mechanism that holds the rule
			-- rather than a second reference to the issue.
			"live_vulnerability_id" ` + t.refNull + ` NULL,
			CONSTRAINT "exploited_here_live_unique" UNIQUE ("live_vulnerability_id", "product_id"),
			CONSTRAINT "exploited_here_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "exploited_here_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "exploited_here_recorder_fk" FOREIGN KEY ("recorded_by")
				REFERENCES "person"("id"),
			CONSTRAINT "exploited_here_clearer_fk" FOREIGN KEY ("cleared_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// Reading a product's records newest first, and reading whether one
		// stands against an issue there. The rule that only one stands is
		// held by the unique constraint above, not this.
		`CREATE INDEX "exploited_here_product_idx" ON "exploited_here" ("product_id", "recorded_at")`,
		`CREATE INDEX "exploited_here_issue_idx" ON "exploited_here" ("vulnerability_id", "product_id")`,

		// A window a deployment says it is under, counted from the moment
		// an attack became known. None ships: a window here is an
		// interpretation of somebody's rules, and the deployment is the one
		// holding them.
		`CREATE TABLE "obligation_window" (
			"id"    ` + t.id + `,
			-- What the window is called, as it was typed. Matched without
			-- regard to capitals through live_name, which holds it folded.
			"name"  ` + t.name + ` NOT NULL,
			-- The window's length in whole hours. Hours rather than days,
			-- because the shortest windows in force anywhere are a day.
			"length_hours" INTEGER NOT NULL,
			-- How long before the end a second notice is raised, in whole
			-- hours, where the window names one. Null is no second notice.
			"lead_hours" INTEGER NULL,
			"declared_by" ` + t.ref + ` NOT NULL,
			"declared_at" ` + t.timestamp + ` NOT NULL,
			-- Retired rather than deleted: a notice recorded against a
			-- window keeps naming it after nobody counts it any more.
			"retired_at" ` + t.timestamp + ` NULL,
			-- The name while the window is in force, and null once it is
			-- retired, so a retired name may be declared again. The same
			-- mechanism a standing record of being exploited uses.
			"live_name" ` + t.name + ` NULL,
			CONSTRAINT "obligation_window_live_unique" UNIQUE ("live_name"),
			CONSTRAINT "obligation_window_declarer_fk" FOREIGN KEY ("declared_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// The products a window is limited to. None is every product: a
		// window is declared once for the deployment and narrowed where the
		// administrator says it applies, which is their statement rather
		// than anything worked out here.
		`CREATE TABLE "obligation_window_product" (
			"window_id"  ` + t.ref + ` NOT NULL,
			"product_id" ` + t.ref + ` NOT NULL,
			CONSTRAINT "obligation_window_product_pk" PRIMARY KEY ("window_id", "product_id"),
			CONSTRAINT "obligation_window_product_window_fk" FOREIGN KEY ("window_id")
				REFERENCES "obligation_window"("id"),
			CONSTRAINT "obligation_window_product_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id")
		)` + t.suffix,

		// Somebody outside told about an attack: who, when, and about what.
		// Append-only, the shape of the record of an advisory going out. A
		// notice recorded in error is answered by recording the correction
		// beside it, because what was said to a regulator is not unsaid by
		// editing a row.
		`CREATE TABLE "told_outside" (
			"id"               ` + t.id + `,
			"exploited_here_id" ` + t.ref + ` NOT NULL,
			-- The window this notice answers, where the person recording it
			-- said so. Their statement rather than a computation: nothing
			-- here decides whether a notice met anything.
			"window_id" ` + t.refNull + ` NULL,
			-- Who was told: a regulator, a customer, a response team.
			"recipient" ` + t.free + ` NOT NULL,
			-- Supplied rather than taken from the clock, for the reason the
			-- moment an attack became known is.
			"told_at"   ` + t.timestamp + ` NOT NULL,
			-- What they were told.
			"said"      ` + t.text + ` NOT NULL,
			"recorded_by" ` + t.ref + ` NOT NULL,
			"recorded_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "told_outside_record_fk" FOREIGN KEY ("exploited_here_id")
				REFERENCES "exploited_here"("id"),
			CONSTRAINT "told_outside_window_fk" FOREIGN KEY ("window_id")
				REFERENCES "obligation_window"("id"),
			CONSTRAINT "told_outside_recorder_fk" FOREIGN KEY ("recorded_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// A record's notices, read for every record the shelf shows.
		`CREATE INDEX "told_outside_record_idx" ON "told_outside" ("exploited_here_id", "told_at")`,
	}
}

// The repositories patch links point into, the commits they name, and the
// branches each commit was found on.
//
// Keyed on the commit rather than on the link. One fix is named by several
// spellings of a link, and by the records of several issues, and the branches
// it is on are a fact about the commit in its repository whichever of them
// asked (REQ-78).
//
// Nothing here records which copy of a repository answered. The copies are
// one replica's disk and these rows are every replica's, so what is kept is
// what the history said rather than where it was read.
func patchBranchBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "patch_repository" (
			"id"           ` + t.id + `,
			-- The address the history is fetched from, as built from a link
			-- rather than as the link spelled it.
			"url"          ` + t.free + ` NOT NULL,
			-- Its digest, because the address is longer than an index key may
			-- be on some engines.
			"url_identity" ` + t.hash + ` NOT NULL,
			-- The host, lowered, so the report of what is fetched from where
			-- can say which an administrator excluded without parsing every
			-- address again.
			"host"         ` + t.name + ` NOT NULL,
			-- When a pass last began a visit, when one last finished, and
			-- what stopped the last one. Two moments for the reason a
			-- supplier has two: a visit that failed still happened, and how
			-- long a repository has been out of reach is the gap between them.
			"fetched_at"   ` + t.timestamp + ` NULL,
			"reached_at"   ` + t.timestamp + ` NULL,
			"failed"       ` + t.free + ` NULL,
			-- How large the copy was when the last visit finished, in bytes.
			-- What an operator sizing the cache reads.
			"held_bytes"   ` + t.refNull + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "patch_repository_url_unique" UNIQUE ("url_identity")
		)` + t.suffix,

		`CREATE TABLE "patch_commit" (
			"id"            ` + t.id + `,
			"repository_id" ` + t.ref + ` NOT NULL,
			-- The commit's name as a link gave it, lowered. Possibly
			-- abbreviated, which the copy resolves.
			"commit_hash"   ` + t.hash + ` NOT NULL,
			-- When the copy was last asked about it. Null is never, which is
			-- what the pass takes first.
			"looked_at"     ` + t.timestamp + ` NULL,
			-- Whether the copy held it when asked. A commit in a pull request
			-- nobody merged, or one a history rewrite dropped, is named by a
			-- link and held by no branch.
			"found"         ` + t.boolean + ` NOT NULL,
			-- How many branches held it, which may be more than are kept
			-- below: a commit early in a long-lived repository is on every
			-- branch cut since.
			"branch_count"  ` + t.ref + ` NOT NULL,
			"created_at"    ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "patch_commit_unique" UNIQUE ("repository_id", "commit_hash"),
			CONSTRAINT "patch_commit_repository_fk" FOREIGN KEY ("repository_id")
				REFERENCES "patch_repository"("id")
		)` + t.suffix,

		// What the pass reads to find a repository's commits due a look.
		`CREATE INDEX "patch_commit_due_idx" ON "patch_commit"
			("repository_id", "looked_at")`,

		`CREATE TABLE "patch_commit_branch" (
			"id"        ` + t.id + `,
			"commit_id" ` + t.ref + ` NOT NULL,
			"branch"    ` + t.name + ` NOT NULL,
			CONSTRAINT "patch_commit_branch_unique" UNIQUE ("commit_id", "branch"),
			CONSTRAINT "patch_commit_branch_commit_fk" FOREIGN KEY ("commit_id")
				REFERENCES "patch_commit"("id")
		)` + t.suffix,
	}
}
