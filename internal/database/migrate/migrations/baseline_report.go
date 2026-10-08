// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"strconv"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// flawReportBaseline declares the report table and its indexes, with whether the
// flaw was found here. A flaw found here has a report like one from outside, so
// a later claim about the same flaw can be ruled a duplicate of it.
func flawReportBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "flaw_report" (
			"id"               ` + t.id + `,
			-- The name this report is reached by, and the one somebody
			-- quotes back to a reporter. Drawn at random rather than
			-- counted: a sequence tells anybody who may ask how many
			-- claims this product has received and when the last one
			-- arrived, which is a disclosure made by the name alone.
			--
			-- Composed rather than a name: it is a product's name and
			-- twelve more characters, and a product may be named at the
			-- full width of one. Sized as a name, a long enough product
			-- minted a reference two engines refuse and SQLite stores,
			-- so the quick loop would never see it.
			"reference"        VARCHAR(` + strconv.Itoa(database.ComposedWidth) + `) NOT NULL,
			-- The product it was reported against.
			--
			-- It is what decides who may read the reporter's name, address
			-- and received date. An issue's identity spans its aliases, so
			-- the same issue turns up in other products the moment a shared
			-- CVE is recorded — and keyed on the issue alone, all of that
			-- was readable by anybody holding triage rights in any of them.
			"product_id"       ` + t.ref + ` NOT NULL,
			-- The issue it turned out to be, where somebody has judged it.
			-- Null is a claim nobody has judged yet, which is the state
			-- every report arrives in and the state a slop report stays in.
			"vulnerability_id" ` + t.refNull + ` NULL,
			-- What was claimed, in the words it was claimed in. It is the
			-- whole substance of a report with no issue: the issue's own
			-- description is where the claim lives once there is one.
			"summary"          ` + t.text + ` NULL,
			-- Who found it, as they gave their name, and how to reach them.
			-- Free text: a reporter is somebody outside this deployment and
			-- has no account here, which is the whole shape of the thing.
			"reported_by"      ` + t.free + ` NULL,
			"contact"          ` + t.free + ` NULL,
			-- How they wish to be credited, which is what the advisory's
			-- acknowledgments section says. Kept apart from the name they
			-- reported under: "anonymous" is a real answer, and so is a
			-- handle that is not the name on the mail.
			"credit"           ` + t.free + ` NULL,
			-- When it arrived, which is what the embargo clock runs from.
			-- A date rather than a moment: the reporter is counting
			-- in days and so are we.
			"received_on"      ` + t.date + ` NULL,
			-- When somebody answered them, and who. Null is the condition
			-- an unacknowledged report reports: prompt acknowledgment is the part of
			-- coordinated disclosure a reporter actually judges, and it is
			-- the step that costs nothing and is missed by being nobody's job.
			"acknowledged_at"  ` + t.timestamp + ` NULL,
			"acknowledged_by"  ` + t.refNull + ` NULL,
			-- When somebody judged the claim, and who. The person who
			-- transcribes a mail is not the person who decides what it is
			-- worth, and a record that cannot tell them apart cannot
			-- evidence either.
			"evaluated_at"     ` + t.timestamp + ` NULL,
			"evaluated_by"     ` + t.refNull + ` NULL,
			"recorded_by"      ` + t.ref + ` NOT NULL,
			"recorded_at"      ` + t.timestamp + ` NOT NULL,
			-- The ruling that answers it, waiting or in force. One at a
			-- time: a report under a ruling cannot be put under a second
			-- one, or accepted as an issue, until the first is withdrawn.
			"ruling_id"        ` + t.refNull + ` NULL,
			-- Whether the flaw was found here rather than sent in. Only one
			-- sent in carries a disclosure date, because only then is
			-- somebody outside counting down to a publication (REQ-37). A
			-- default rather than a fill: a report is from outside unless
			-- somebody says otherwise.
			"found_here"       ` + t.boolean + ` DEFAULT FALSE NOT NULL,
			CONSTRAINT "flaw_report_reference_unique" UNIQUE ("reference"),
			CONSTRAINT "flaw_report_issue_unique" UNIQUE ("vulnerability_id"),
			CONSTRAINT "flaw_report_issue_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "flaw_report_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "flaw_report_by_fk" FOREIGN KEY ("recorded_by") REFERENCES "person"("id"),
			CONSTRAINT "flaw_report_answered_by_fk" FOREIGN KEY ("acknowledged_by") REFERENCES "person"("id"),
			CONSTRAINT "flaw_report_judged_by_fk" FOREIGN KEY ("evaluated_by") REFERENCES "person"("id"),
			CONSTRAINT "flaw_report_ruling_fk" FOREIGN KEY ("ruling_id") REFERENCES "report_ruling"("id")
		)` + t.suffix,

		// The unacknowledged sweep's index: the reports nobody has answered.
		`CREATE INDEX "flaw_report_unanswered_idx"
			ON "flaw_report" ("acknowledged_at", "received_on")`,

		// One product's reports, newest first, which is the list somebody
		// works through.
		`CREATE INDEX "flaw_report_product_idx"
			ON "flaw_report" ("product_id", "recorded_at")`,

		`CREATE INDEX "flaw_report_ruling_idx"
			ON "flaw_report" ("ruling_id")`,
	}
}

// What somebody told us, and what became of it.
//
// A report is the record that a claim arrived, and it stands whether or not
// the claim turns out to be a flaw. Without that, a bogus report either
// pollutes the findings with an issue nobody believes or goes unrecorded —
// and an unrecorded report destroys the evidence that it was received and
// answered, which is the whole purpose of the table.
//
// It comes before the attachment table because a report carries files of its
// own: the screenshot is often the whole of what was sent.
//
// Two of the fields do work beyond the record. The received date is what
// the embargo clock runs from: a report arriving on 1 June and typed
// in on 15 June otherwise puts our clock two weeks behind the one the reporter
// has a publication scheduled against, and they are the party who will publish
// regardless. The acknowledged date is what makes an unacknowledged report a
// condition somebody is told about.
//
// A row per issue where there is one. A flaw recorded against four builds is
// one report from one person, and four copies of their address is four places
// for it to be wrong.
//
// Researchers are assumed to email, so these are facts somebody has in
// hand when they type the record in rather than ceremony. A public intake form
// stays out of scope; this is the inside half.
func rulingBaseline(t *columnTypes) []string {
	return []string{
		// One act of saying what one or more claims are, where the answer is
		// not an issue here. It is kept apart from the reports it covers
		// because one act answers many of them — twenty slop reports rejected
		// in one sentence with one approval — and the approval is of that act
		// and those words.
		`CREATE TABLE "report_ruling" (
			"id"           ` + t.id + `,
			"product_id"   ` + t.ref + ` NOT NULL,
			-- duplicate, not-reproducible, out-of-scope or rejected. A
			-- report accepted as an issue points at that issue instead.
			"disposition"  ` + t.kind + ` NOT NULL,
			-- Why, as markdown. Never edited: an approval is of these words,
			-- and words that could change underneath it would be an approval
			-- of nothing in particular.
			"reasoning"    ` + t.text + ` NULL,
			-- The open issue a duplicate points at. Null on every other
			-- disposition.
			"duplicate_of" ` + t.refNull + ` NULL,
			"proposed_by"  ` + t.ref + ` NOT NULL,
			"proposed_at"  ` + t.timestamp + ` NOT NULL,
			-- Who agreed, where the disposition takes a second person.
			"approved_by"  ` + t.refNull + ` NULL,
			"approved_at"  ` + t.timestamp + ` NULL,
			-- When it took effect: at once where nobody else has to agree,
			-- on approval where somebody does. Null is waiting.
			"settled_at"   ` + t.timestamp + ` NULL,
			-- Taken back, before or after it took effect. The reports it
			-- covered return to the inbox, and this row stays as the record
			-- of what was said.
			"withdrawn_by" ` + t.refNull + ` NULL,
			"withdrawn_at" ` + t.timestamp + ` NULL,
			CONSTRAINT "report_ruling_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "report_ruling_duplicate_fk" FOREIGN KEY ("duplicate_of") REFERENCES "vulnerability"("id"),
			CONSTRAINT "report_ruling_proposed_by_fk" FOREIGN KEY ("proposed_by") REFERENCES "person"("id"),
			CONSTRAINT "report_ruling_approved_by_fk" FOREIGN KEY ("approved_by") REFERENCES "person"("id"),
			CONSTRAINT "report_ruling_withdrawn_by_fk" FOREIGN KEY ("withdrawn_by") REFERENCES "person"("id")
		)` + t.suffix,

		// What is waiting in one product, which is the list an approver
		// works through.
		`CREATE INDEX "report_ruling_waiting_idx"
			ON "report_ruling" ("product_id", "settled_at", "withdrawn_at")`,

		// A duplicate is read from the issue it points at.
		`CREATE INDEX "report_ruling_duplicate_idx"
			ON "report_ruling" ("duplicate_of")`,

		// Which reports a ruling covered, for good. The live pointer on the
		// report is cleared when a ruling is withdrawn, and this is what
		// still says what the withdrawn ruling was about.
		`CREATE TABLE "report_ruled" (
			"ruling_id"      ` + t.ref + ` NOT NULL,
			"flaw_report_id" ` + t.ref + ` NOT NULL,
			CONSTRAINT "report_ruled_pk" PRIMARY KEY ("ruling_id", "flaw_report_id"),
			CONSTRAINT "report_ruled_ruling_fk" FOREIGN KEY ("ruling_id") REFERENCES "report_ruling"("id"),
			CONSTRAINT "report_ruled_report_fk" FOREIGN KEY ("flaw_report_id") REFERENCES "flaw_report"("id")
		)` + t.suffix,

		`CREATE INDEX "report_ruled_report_idx"
			ON "report_ruled" ("flaw_report_id")`,
	}
}

// A file hanging off an issue or a report, and the record of it that outlives
// the bytes.
//
// The bytes are not here. What this table holds is the reference
// the text uses, what the file is, where it went, who put it there, and — when
// somebody has to take a file back out — what was removed and why.
//
// It hangs off the issue in the product, which is the unit a decision, an
// embargo and a comment already use. Not a finding row: text is written against
// a decision and a decision covers every place an issue sits at, so binding a
// file to whichever of forty-eight rows somebody was looking at would lose it
// the day that row closed while its siblings stayed open.
//
// Or off a report, which is the other thing a file arrives with. A report
// that has not been judged has no issue to hang anything on, and the
// screenshot is often the whole of what was sent — so a file arriving with
// one is kept against the report and stays there once the report gains an
// issue, because what was sent is a fact about the report.
//
// There is no visibility column, deliberately. Whether a file may be read
// is whether the thing it hangs off may be read, asked at the moment of the
// request. A copy taken at upload would still say "private" after the embargo
// it documents had ended, which is the shape of every stale-value defect:
// correct when written, wrong from then on, and nothing reports it.
func attachmentBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "attachment" (
			"id"               ` + t.id + `,
			-- What the text refers to, and the only identifier that
			-- ever leaves this deployment. Unguessable rather than sequential:
			-- authorization is what protects a file, but a reference somebody
			-- can enumerate turns "which issues have attachments" into a
			-- question an outsider can ask by counting.
			"token"            ` + t.name + ` NOT NULL,
			-- What it is about. The product always, because an issue is
			-- only an issue somewhere: the same CVE in two products is two
			-- pieces of work and two sets of readers.
			"product_id"       ` + t.ref + ` NOT NULL,
			-- And then one of the two things a file hangs off: an issue, or
			-- a report nobody has turned into one. Exactly one is set, which
			-- the store asks and the schema does not: MySQL parses a CHECK
			-- and ignores it until 8.0.16 and the floor here is 8.0, so the
			-- constraint would hold on three engines of four. No migration
			-- here declares one.
			"vulnerability_id" ` + t.refNull + ` NULL,
			"flaw_report_id"   ` + t.refNull + ` NULL,
			-- What it was called when it arrived, for the disposition header.
			-- Kept as given and never used as a path.
			"filename"         ` + t.text + ` NOT NULL,
			-- The type **we** decided, never the one that was uploaded.
			-- Stored because it is what gets served, and because
			-- deciding it again later would apply today's allowlist to a file
			-- accepted under an older one.
			"content_type"     ` + t.name + ` NOT NULL,
			"size_bytes"       BIGINT NOT NULL,
			-- The digest of what was stored. Not the key: two identical files
			-- are two attachments, because redacting one must not blank the
			-- other. It is here so that a redaction can say what it
			-- removed after the bytes are gone.
			"digest"           ` + t.hash + ` NOT NULL,
			-- Where it went in the store. Ours to choose and never derived
			-- from the filename, so nothing a person typed reaches a path.
			"object_key"       ` + t.name + ` NOT NULL,
			"uploaded_by"      ` + t.ref + ` NOT NULL,
			"uploaded_at"      ` + t.timestamp + ` NOT NULL,
			-- When saved text first referred to it. Null is an upload nothing
			-- points at — somebody dragged a file in and closed the tab — and
			-- that is what the sweep collects. Set once and never
			-- cleared: text is append-only, so a reference that existed goes
			-- on existing in the revision that made it.
			"attached_at"      ` + t.timestamp + ` NULL,
			-- The tombstone. The row stays and the reference in the
			-- text stays; what goes is the file, and these three say that it
			-- was deliberate, who did it and why. A reason is required of them
			-- for the same reason moving a disclosure date is.
			"redacted_at"      ` + t.timestamp + ` NULL,
			"redacted_by"      ` + t.refNull + ` NULL,
			"redacted_reason"  ` + t.text + ` NULL,
			CONSTRAINT "attachment_token_unique" UNIQUE ("token"),
			CONSTRAINT "attachment_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "attachment_vulnerability_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "attachment_report_fk" FOREIGN KEY ("flaw_report_id") REFERENCES "flaw_report"("id"),
			CONSTRAINT "attachment_uploaded_by_fk" FOREIGN KEY ("uploaded_by") REFERENCES "person"("id"),
			CONSTRAINT "attachment_redacted_by_fk" FOREIGN KEY ("redacted_by") REFERENCES "person"("id")
		)` + t.suffix,

		// Everything hanging off one issue, which is what a finding screen
		// lists.
		`CREATE INDEX "attachment_issue_idx"
			ON "attachment" ("product_id", "vulnerability_id")`,

		// Everything that arrived with one report, which is what a report
		// screen lists.
		`CREATE INDEX "attachment_report_idx"
			ON "attachment" ("flaw_report_id")`,

		// Anything nothing points at yet, for the sweep. Leading with the
		// column the sweep tests for null, so it walks only the candidates
		// rather than every attachment ever made.
		`CREATE INDEX "attachment_unattached_idx"
			ON "attachment" ("attached_at", "uploaded_at")`,
	}
}
