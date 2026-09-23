// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"strconv"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

func init() {
	goose.AddMigrationContext(upReport, downReport)
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
func upReport(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	return apply(ctx, tx, reportStatements(t))
}

func reportStatements(t *columnTypes) []string {
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

func downReport(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "report_ruled", "flaw_report", "report_ruling")
}
