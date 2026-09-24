// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"strconv"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// v0.3.0's declaration of the report table, and its indexes.
//
// v0.2.0's, with whether the flaw was found here. v0.2.0 recorded a flaw found
// here with no report at all, so it kept nothing a later claim about the same
// flaw could be ruled a duplicate of.
func reportV030(t *columnTypes) []string {
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
