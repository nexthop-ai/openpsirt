// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// vulnerabilityBaseline declares the vulnerability table: the issue each row is
// read as, and the day the known-exploited catalog listed it.
func vulnerabilityBaseline(t *columnTypes) []string {
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

// aliasBaseline declares the names an issue answers to, with whether a person
// typed the name, and its index.
func aliasBaseline(t *columnTypes) []string {
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

// mergeBaseline declares the record of one issue merged into another, and of a
// decision a merge superseded.
func mergeBaseline(t *columnTypes) []string {
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

// A scan run's findings, and their subject.
//
// A vulnerability is one issue however many names it goes by. The same issue
// arrives as a national identifier from one database and an advisory
// identifier from another, and which one a scanner calls primary is a
// preference of whichever source it consulted rather than a property of the
// issue. Keying anything on that choice would lapse every decision the day a
// scanner changed its mind, so the aliases resolve to one row.
//
// A finding is a vulnerability at a place: the component, and the thing that
// directly pulled it in. One issue in a shared library is one finding per
// consumer, because different consumers use different parts of what they
// depend on.
//
// Findings are held over intervals against scan runs, the same shape the graph
// uses, for the same reason: re-scanning nightly against a database that moved
// slightly must write only what changed.
func issueBaseline(t *columnTypes) []string {
	return []string{

		// Every name an issue is known by, including the one it is filed
		// under. A report naming any of them finds the same row.
		`CREATE TABLE "vulnerability_reference" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"url"              ` + t.free + ` NOT NULL,
			-- What it appears to be, as far as the address reveals. A patch is
			-- the one worth telling apart: somebody deciding whether to
			-- backport rather than upgrade needs it, and hunting for it by
			-- hand is the step that does not happen when a thousand others are
			-- waiting.
			"kind"             ` + t.kind + ` NOT NULL,
			-- The hash of the address, because the address itself is longer
			-- than an index key may be on some engines.
			"url_identity"     ` + t.hash + ` NOT NULL,
			CONSTRAINT "vulnerability_reference_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "vulnerability_reference_unique" UNIQUE ("vulnerability_id", "url_identity")
		)` + t.suffix,

		// The kind of flaw, by the classification the data carries.
		//
		// A row per weakness rather than one comma-joined column, which is the
		// shape every other multi-valued attribute here has. Packed into one
		// column it was queried on anyway — the class-of-flaw filter — and the
		// only way to ask "is CWE-79 in this list" without a table is a
		// substring match, which answers CWE-79 for a search for CWE-7 unless
		// it is written as four separate patterns to respect the commas. Four
		// unindexable patterns per name asked, against every issue, where a
		// table answers with one indexed lookup.
		//
		// A report usually names the same weakness from several sources, so
		// the pair is unique: a re-scan of the same data writes nothing.
		`CREATE TABLE "vulnerability_weakness" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- Upper-cased on the way in, like every other identifier compared
			-- exactly: CWE names are written CWE-79 everywhere they are
			-- published, and a feed that shouts or whispers one should not
			-- make two rows of it.
			"cwe"              ` + t.name + ` NOT NULL,
			-- Whether this is the one the data calls the root cause.
			--
			-- A published advisory states one weakness, and an issue is
			-- commonly classified as several. Which one is stated cannot be
			-- picked here: choosing the lowest number, or the first read, is
			-- an answer with nothing behind it. The feeds say which is primary
			-- and a person recording a flaw names theirs first, so the answer
			-- is carried rather than invented.
			"is_primary"       ` + t.boolean + ` NOT NULL,
			CONSTRAINT "vulnerability_weakness_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "vulnerability_weakness_unique" UNIQUE ("vulnerability_id", "cwe")
		)` + t.suffix,

		// The class-of-flaw filter's index: every issue of one kind.
		`CREATE INDEX "vulnerability_weakness_cwe_idx" ON "vulnerability_weakness" ("cwe")`,

		// Each published rating of an issue, one per generation of the
		// scoring scheme. A report commonly rates one issue under version 3
		// and version 4, and the two are different judgments rather than two
		// spellings of one: the screen shows the newest, and a published
		// advisory states the one its format has a field for.
		//
		// The first stated in each generation is kept whole, number and
		// vector together, so the two never come from different publishers.
		`CREATE TABLE "vulnerability_rating" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The major version of the scheme: 2, 3 or 4. Version 3.0 and 3.1
			-- are one generation, because they share one formula and one
			-- field in every format that carries them.
			"generation"       ` + t.ref + ` NOT NULL,
			"score_centi"      ` + t.ref + ` NOT NULL,
			"vector"           ` + t.free + ` NOT NULL,
			-- Unbounded, like the three the issue carries beside its own
			-- score, and for the same reason.
			"score_version"    ` + t.free + ` NULL,
			"score_source"     ` + t.free + ` NULL,
			"score_kind"       ` + t.free + ` NULL,
			CONSTRAINT "vulnerability_rating_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "vulnerability_rating_unique" UNIQUE ("vulnerability_id", "generation")
		)` + t.suffix,

		// One execution of a scanner over one variant. Recorded whether it ran
		// here or arrived from a producer, because a report that averages two
		// scanners without saying so is worse than no report.
		`CREATE TABLE "scan_run" (
			"id"               ` + t.id + `,
			"target_id"        ` + t.ref + ` NOT NULL,
			-- What the scanner calls itself and what it was reading, both
			-- taken verbatim from its output and bounded by nothing on the
			-- way in — so they are the producer-supplied slot rather than
			-- the indexed-name one. None of the three is indexed or unique.
			"scanner"          ` + t.free + ` NOT NULL,
			"scanner_version"  ` + t.free + ` NULL,
			"database_version" ` + t.free + ` NULL,
			"ran_here"         ` + t.boolean + ` NOT NULL,
			"started_at"       ` + t.timestamp + ` NOT NULL,
			"finished_at"      ` + t.timestamp + ` NULL,
			"failure"          ` + t.text + ` NULL,
			-- What the scanner said while succeeding: a qualification on the
			-- answer rather than a reason there is none. Kept apart from the
			-- failure above because a run that warned and a run that failed
			-- are different things, and one column holding either makes them
			-- one. Told to match Go binaries with no function symbols the
			-- scanner says so and falls back to module granularity, which can
			-- report a component as affected when the vulnerable function is
			-- not linked in — that qualifies every finding of that run.
			"caution"          ` + t.text + ` NULL,
			CONSTRAINT "scan_run_target_id_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id")
		)` + t.suffix,
	}
}

// What one product thinks of an issue, as against what was published about it.
//
// Recorded against the issue rather than against a place, and against one
// product rather than against the deployment. Keyed to a place it would have
// to be repeated at each one and would lapse on a version change that had
// nothing to do with it: the rating did not stop being wrong because somebody
// rebuilt. Keyed to nothing at all it was one statement for everybody, which
// let a rating made by somebody holding one product move the deadline and the
// triage line in a product they cannot see, and refused a second team any
// rating of their own — a rating is a judgment about how a component is used,
// and two products do not use one the same way.
//
// The rating in force lives in "issue_rating", one row per issue and product,
// and everything that ranks or filters reads it through one expression with
// the published rating as its fallback. That keeps the claim in one place and
// the reading of it in one place — this project's own recurring lesson is that
// every identity and expiry bug came from letting one fact into two rules.
//
// Nothing inherits. A product nobody has rated the issue in shows the
// published rating until somebody on that team looks, because a rating
// arriving from a product they cannot see is the thing this shape removes.
//
// The published rating is never overwritten. A rating of ours shown where the
// world's rating goes reads as the world's, and the first person to check
// against the public record finds a discrepancy nobody declared.
func issueRatingBaseline(t *columnTypes) []string {
	return []string{

		// The rating in force, one row per issue and product.
		//
		// Separate from the claim above because a milder rating waits for a
		// second person: a claim exists before it decides anything, and what
		// ranks has to be readable without knowing which claims are live. A
		// row is written when a rating takes effect and removed when it is
		// withdrawn, so its presence is the whole of "somebody here rates
		// this differently".
		//
		// Read by a left join keyed on the issue and the product, with the
		// published rating as the fallback, through one expression. The
		// alternative was a copy on every finding, and a finding opened
		// tomorrow by a component that newly pulls the library in would carry
		// the rating only if the applying path remembered to fetch it. A
		// joined table cannot drift that way.
		`CREATE TABLE "issue_rating" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			"severity"         ` + t.kind + ` NOT NULL,
			CONSTRAINT "issue_rating_unique" UNIQUE ("vulnerability_id", "product_id"),
			CONSTRAINT "issue_rating_vulnerability_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "issue_rating_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id")
		)` + t.suffix,
	}
}

// A note for whoever decides, left without recording a judgment.
//
// **There was nowhere to put one.** A comment hangs off a claim, and the
// finding screen shows the box only where a claim already exists, so the first
// person to say anything about an issue had to record a judgment in order to
// say it. Assignment carries no message either: it takes a person or a team
// and nothing else.
//
// **Keyed on the issue and the product**, the way a rating is, and for the
// same reason. A row in the findings list is one issue at one fold, and one
// issue is often several rows: measured against the seeded image, 786 of 5,840
// open issues sit on more than one row, the worst at eleven, across
// golang.org/x/net and the standard library. A note attached to a row would
// have been written on one of eleven and hidden from the other ten.
//
// **Not merged into a claim's thread.** A claim is keyed on a place and a note
// on an issue, so they cannot become one record — two threads rendered near
// each other, and the claim's record stays exactly what people wrote about the
// claim. That matters where an approval points at one revision of a
// justification and editing the text withdraws it.
//
// **What it said before is kept**, the way a claim comment's is: a note is
// part of the record that goes public at disclosure, and a record whose
// earlier text is unrecoverable is readable rather than checkable.
func issueNoteBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "issue_note" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			"product_id"       ` + t.ref + ` NOT NULL,
			-- What was written, as source. Stored the way every other piece of
			-- text somebody typed is: rendering happens on the way out, and
			-- text stored years ago predates rules written since.
			"body"             ` + t.text + ` NOT NULL,
			"written_by"       ` + t.ref + ` NOT NULL,
			"written_at"       ` + t.timestamp + ` NOT NULL,
			-- That the author changed it. What it said before is in the table
			-- below.
			"edited_at"        ` + t.timestamp + ` NULL,
			CONSTRAINT "issue_note_issue_fk" FOREIGN KEY ("vulnerability_id")
				REFERENCES "vulnerability"("id"),
			CONSTRAINT "issue_note_product_fk" FOREIGN KEY ("product_id")
				REFERENCES "product"("id"),
			CONSTRAINT "issue_note_author_fk" FOREIGN KEY ("written_by")
				REFERENCES "person"("id")
		)` + t.suffix,

		// A thread is read whole, oldest first, so the identifier is in the
		// key rather than sorted afterwards.
		`CREATE INDEX "issue_note_thread_idx" ON "issue_note" ("vulnerability_id", "product_id", "id")`,

		// What a note said before it was changed. The previous text, written
		// when it is replaced, rather than every version including the current
		// one: the note row holds what it says now, and this holds what it
		// stopped saying.
		`CREATE TABLE "issue_note_revision" (
			"id"          ` + t.id + `,
			"note_id"     ` + t.ref + ` NOT NULL,
			-- Which version this was, counting from one. The current text is
			-- one past the highest here.
			"ordinal"     ` + t.ref + ` NOT NULL,
			"body"        ` + t.text + ` NOT NULL,
			-- When it stopped saying that. Who wrote it is on the note: only
			-- its author may change one, so a revision has no separate author.
			"replaced_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "issue_note_revision_fk" FOREIGN KEY ("note_id")
				REFERENCES "issue_note"("id"),
			CONSTRAINT "issue_note_revision_once" UNIQUE ("note_id", "ordinal")
		)` + t.suffix,
	}
}
