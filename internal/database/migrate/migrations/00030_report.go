// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upReport, downReport)
}

// Who told us, and when.
//
// **Without this the coordinated-disclosure timeline cannot be evidenced at
// all** — received, acknowledged, triaged, fixed, disclosed — and the
// advisory's acknowledgments section is empty, which is the part a researcher
// reads first.
//
// **Two of the fields do work beyond the record.** The received date is what
// the embargo clock runs from: a report arriving on 1 June and typed
// in on 15 June otherwise puts our clock two weeks behind the one the reporter
// has a publication scheduled against, and they are the party who will publish
// regardless. The acknowledged date is what makes an unacknowledged report a
// condition somebody is told about.
//
// **A row per issue, not per finding.** A flaw recorded against four builds is
// one report from one person, and four copies of their address is four places
// for it to be wrong.
//
// **Researchers are assumed to email**, so these are facts somebody has in
// hand when they type the record in rather than ceremony. A public intake form
// stays out of scope; this is the inside half.
func upReport(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "flaw_report" (
			"id"               ` + t.id + `,
			"vulnerability_id" ` + t.ref + ` NOT NULL,
			-- The product it was reported against.
			--
			-- A report is one per issue, not one per finding: a flaw
			-- recorded against four builds is one report from one person.
			-- But an issue's identity spans its aliases, so the same issue
			-- turns up in other products the moment a shared CVE is
			-- recorded — and without this the reporter's name, address and
			-- received date were readable by anybody holding triage rights
			-- in any of them.
			"product_id"       ` + t.ref + ` NOT NULL,
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
			"recorded_by"      ` + t.ref + ` NOT NULL,
			"recorded_at"      ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "flaw_report_issue_unique" UNIQUE ("vulnerability_id"),
			CONSTRAINT "flaw_report_issue_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "flaw_report_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "flaw_report_by_fk" FOREIGN KEY ("recorded_by") REFERENCES "person"("id")
		)` + t.suffix,

		// What the unacknowledged sweep reads: the reports nobody has answered.
		`CREATE INDEX "flaw_report_unanswered_idx"
			ON "flaw_report" ("acknowledged_at", "received_on")`,
	}

	return apply(ctx, tx, statements)
}

func downReport(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "flaw_report")
}
