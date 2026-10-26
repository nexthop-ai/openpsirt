// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// flawReportV0110 is v0.11.0's declaration of the report table and the tables
// that make a report a case: its revisions, its notes, its correspondence and
// who has held it.
//
// The baseline's report, with a title and a holder, and without the
// acknowledged stamp: the first message sent to the reporter is the
// acknowledgement.
func flawReportV0110(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "flaw_report" (
			"id"               ` + t.id + `,
			-- The name this report is reached by, and the one somebody
			-- quotes back to a reporter. Drawn at random rather than
			-- counted: a sequence tells anybody who may ask how many
			-- claims this product has received and when the last one
			-- arrived. Composed of a product's name and twelve more
			-- characters, so it is sized as a composed value.
			"reference"        VARCHAR(` + strconv.Itoa(database.ComposedWidth) + `) NOT NULL,
			-- A line naming the claim, as somebody here wrote it. Optional:
			-- the claim is what is evaluated and answered.
			"title"            ` + t.free + ` NULL,
			-- The product it was reported against, which decides who may
			-- read it.
			"product_id"       ` + t.ref + ` NOT NULL,
			-- The issue it turned out to be, where somebody accepted it as
			-- one. Null is a claim nobody has judged, and one a ruling
			-- answers.
			"vulnerability_id" ` + t.refNull + ` NULL,
			-- What was claimed, as it stands now. What it said before an edit
			-- is in the revisions.
			"summary"          ` + t.text + ` NULL,
			-- Who sent it, how to reach them and how they wish to be
			-- credited. Free text: a reporter has no account here.
			"reported_by"      ` + t.free + ` NULL,
			"contact"          ` + t.free + ` NULL,
			"credit"           ` + t.free + ` NULL,
			-- The day it arrived, which the embargo runs from.
			"received_on"      ` + t.date + ` NULL,
			-- When somebody judged the claim, and who.
			"evaluated_at"     ` + t.timestamp + ` NULL,
			"evaluated_by"     ` + t.refNull + ` NULL,
			"recorded_by"      ` + t.ref + ` NOT NULL,
			"recorded_at"      ` + t.timestamp + ` NOT NULL,
			-- The ruling that answers it, waiting or in force.
			"ruling_id"        ` + t.refNull + ` NULL,
			-- Whether the flaw was found here rather than sent in.
			"found_here"       ` + t.boolean + ` DEFAULT FALSE NOT NULL,
			-- The party holding it: a person, or a team whose queue it sits
			-- in. Null is a report nobody holds.
			"assigned_to"      ` + t.refNull + ` NULL,
			"assigned_at"      ` + t.timestamp + ` NULL,
			CONSTRAINT "flaw_report_reference_unique" UNIQUE ("reference"),
			CONSTRAINT "flaw_report_issue_unique" UNIQUE ("vulnerability_id"),
			CONSTRAINT "flaw_report_issue_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id"),
			CONSTRAINT "flaw_report_product_fk" FOREIGN KEY ("product_id") REFERENCES "product"("id"),
			CONSTRAINT "flaw_report_by_fk" FOREIGN KEY ("recorded_by") REFERENCES "person"("id"),
			CONSTRAINT "flaw_report_judged_by_fk" FOREIGN KEY ("evaluated_by") REFERENCES "person"("id"),
			CONSTRAINT "flaw_report_ruling_fk" FOREIGN KEY ("ruling_id") REFERENCES "report_ruling"("id"),
			CONSTRAINT "flaw_report_holder_fk" FOREIGN KEY ("assigned_to") REFERENCES "party"("id")
		)` + t.suffix,

		// One product's reports, newest first, which is the list somebody
		// works through.
		`CREATE INDEX "flaw_report_product_idx"
			ON "flaw_report" ("product_id", "recorded_at")`,

		`CREATE INDEX "flaw_report_ruling_idx"
			ON "flaw_report" ("ruling_id")`,

		// What one party holds and what nobody holds, product by product.
		`CREATE INDEX "flaw_report_holder_idx"
			ON "flaw_report" ("assigned_to", "product_id")`,

		// What a report said before each edit. The report row holds what it
		// says now; each row here holds what one edit replaced.
		`CREATE TABLE "flaw_report_revision" (
			"id"             ` + t.id + `,
			"flaw_report_id" ` + t.ref + ` NOT NULL,
			-- Which version this was, counting from one. The report as it
			-- stands is one past the highest here, and version one is the
			-- report as it was first recorded.
			"ordinal"        ` + t.ref + ` NOT NULL,
			"title"          ` + t.free + ` NULL,
			"summary"        ` + t.text + ` NULL,
			"reported_by"    ` + t.free + ` NULL,
			"contact"        ` + t.free + ` NULL,
			"credit"         ` + t.free + ` NULL,
			"received_on"    ` + t.date + ` NULL,
			-- Who replaced it, and when.
			"replaced_by"    ` + t.ref + ` NOT NULL,
			"replaced_at"    ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "flaw_report_revision_report_fk" FOREIGN KEY ("flaw_report_id")
				REFERENCES "flaw_report"("id"),
			CONSTRAINT "flaw_report_revision_by_fk" FOREIGN KEY ("replaced_by")
				REFERENCES "person"("id"),
			CONSTRAINT "flaw_report_revision_once" UNIQUE ("flaw_report_id", "ordinal")
		)` + t.suffix,

		// A note somebody here wrote on a report, which says something to
		// whoever works it and records no judgment.
		`CREATE TABLE "report_note" (
			"id"             ` + t.id + `,
			"flaw_report_id" ` + t.ref + ` NOT NULL,
			"body"           ` + t.text + ` NOT NULL,
			"written_by"     ` + t.ref + ` NOT NULL,
			"written_at"     ` + t.timestamp + ` NOT NULL,
			-- When its author last changed it. What it said before is in the
			-- note's revisions.
			"edited_at"      ` + t.timestamp + ` NULL,
			CONSTRAINT "report_note_report_fk" FOREIGN KEY ("flaw_report_id")
				REFERENCES "flaw_report"("id"),
			CONSTRAINT "report_note_author_fk" FOREIGN KEY ("written_by")
				REFERENCES "person"("id")
		)` + t.suffix,
		`CREATE INDEX "report_note_thread_idx" ON "report_note" ("flaw_report_id", "id")`,

		// What a note said before it was changed. Only its author changes
		// one, so a revision has no author of its own.
		`CREATE TABLE "report_note_revision" (
			"id"          ` + t.id + `,
			"note_id"     ` + t.ref + ` NOT NULL,
			"ordinal"     ` + t.ref + ` NOT NULL,
			"body"        ` + t.text + ` NOT NULL,
			"replaced_at" ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "report_note_revision_fk" FOREIGN KEY ("note_id")
				REFERENCES "report_note"("id"),
			CONSTRAINT "report_note_revision_once" UNIQUE ("note_id", "ordinal")
		)` + t.suffix,

		// One message between this deployment and the reporter, as somebody
		// here recorded it. Nothing is sent from here: the row records a
		// message somebody sent or received elsewhere.
		`CREATE TABLE "report_message" (
			"id"             ` + t.id + `,
			"flaw_report_id" ` + t.ref + ` NOT NULL,
			-- sent or received.
			"direction"      ` + t.kind + ` NOT NULL,
			-- The day the message was sent or received.
			"dated"          ` + t.date + ` NOT NULL,
			-- The message, pasted or summarized, as markdown. Null on the
			-- acknowledgement a v0.10.0 database recorded, which held no
			-- text.
			"body"           ` + t.text + ` NULL,
			"logged_by"      ` + t.ref + ` NOT NULL,
			"logged_at"      ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "report_message_report_fk" FOREIGN KEY ("flaw_report_id")
				REFERENCES "flaw_report"("id"),
			CONSTRAINT "report_message_by_fk" FOREIGN KEY ("logged_by")
				REFERENCES "person"("id")
		)` + t.suffix,
		// A report's log in order, and whether anything was sent, which is
		// what the unanswered condition asks.
		`CREATE INDEX "report_message_log_idx"
			ON "report_message" ("flaw_report_id", "direction", "dated")`,

		// Every change of who holds a report, for its history. The report row
		// holds the holder now.
		`CREATE TABLE "report_assignment" (
			"id"             ` + t.id + `,
			"flaw_report_id" ` + t.ref + ` NOT NULL,
			-- The party it went to. Null is handed back to nobody.
			"assigned_to"    ` + t.refNull + ` NULL,
			-- The person who did it. Null where a standing rule placed it.
			"assigned_by"    ` + t.refNull + ` NULL,
			-- The standing rule that placed it, where one did.
			"routed_by"      ` + t.refNull + ` NULL,
			"assigned_at"    ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "report_assignment_report_fk" FOREIGN KEY ("flaw_report_id")
				REFERENCES "flaw_report"("id"),
			CONSTRAINT "report_assignment_party_fk" FOREIGN KEY ("assigned_to")
				REFERENCES "party"("id"),
			CONSTRAINT "report_assignment_by_fk" FOREIGN KEY ("assigned_by")
				REFERENCES "person"("id"),
			CONSTRAINT "report_assignment_rule_fk" FOREIGN KEY ("routed_by")
				REFERENCES "routing_rule"("id")
		)` + t.suffix,
		`CREATE INDEX "report_assignment_report_idx"
			ON "report_assignment" ("flaw_report_id", "assigned_at")`,
	}
}

// routingRuleV0110 is v0.11.0's declaration of the routing rule table.
//
// The baseline's, with whether a rule places vulnerability reports. Derived
// from the baseline's declaration; no release between changed it.
func routingRuleV0110(t *columnTypes) []string {
	made, indexes, err := pick(routingBaseline(t), "routing_rule")
	if err != nil {
		panic(err)
	}
	made = withColumn(made, `"beneath"    `+t.name+` NULL,`,
		`-- Whether this rule places the product's vulnerability reports
			-- rather than findings. A report sits at no component, so a rule
			-- placing reports names neither key.
			"reports"    `+t.boolean+` DEFAULT FALSE NOT NULL,`)
	return append([]string{made}, indexes...)
}

// reportCaseV0110 makes a report a case: it gains a title and a holder, the
// tables of its revisions, notes, correspondence and holders are made, every
// acknowledgement v0.10.0 recorded becomes the first message sent, and the
// acknowledged stamp is removed. A routing rule gains whether it places
// reports.
//
// Every step is stepped over where a stopped upgrade already made it, because
// MySQL and MariaDB commit each change as it is made.
func reportCaseV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	declared := flawReportV0110(u.t)
	for _, table := range []string{"report_message", "flaw_report_revision", "report_note",
		"report_note_revision", "report_assignment"} {
		if present, err := u.hasColumn(table, "id"); err != nil {
			return err
		} else if !present {
			if err := u.create(declared, table); err != nil {
				return err
			}
		}
	}

	acknowledged, err := u.hasColumn("flaw_report", "acknowledged_at")
	if err != nil {
		return err
	}
	if acknowledged {
		if err := acknowledgedAsSentV0110(ctx, tx); err != nil {
			return err
		}
		if held, err := u.hasIndex("flaw_report", "flaw_report_unanswered_idx"); err != nil {
			return err
		} else if held {
			if err := dropIndex(ctx, tx.Tx, "flaw_report", "flaw_report_unanswered_idx"); err != nil {
				return err
			}
		}
		if err := u.dropForeignKey("flaw_report", "flaw_report_answered_by_fk"); err != nil {
			return err
		}
	}

	c := change{table: "flaw_report"}
	for _, column := range []string{"title", "assigned_to", "assigned_at"} {
		present, err := u.hasColumn("flaw_report", column)
		if err != nil {
			return err
		}
		if !present {
			c.add = append(c.add, added{column: column})
		}
	}
	for _, column := range []string{"acknowledged_at", "acknowledged_by"} {
		present, err := u.hasColumn("flaw_report", column)
		if err != nil {
			return err
		}
		if present {
			c.drop = append(c.drop, column)
		}
	}
	if len(c.add) > 0 || len(c.drop) > 0 {
		if u.engine != database.SQLite {
			holder, err := u.hasForeignKey("flaw_report", "flaw_report_holder_fk")
			if err != nil {
				return err
			}
			if !holder {
				c.constraints = []string{"flaw_report_holder_fk"}
			}
		}
		if err := u.change(declared, c); err != nil {
			return err
		}
	}
	// Made once and never replaced: MySQL and MariaDB adopt it for the
	// holder's foreign key and refuse to drop it on a later start.
	if held, err := u.hasIndex("flaw_report", "flaw_report_holder_idx"); err != nil {
		return err
	} else if !held {
		if err := u.index(declared, "flaw_report", "flaw_report_holder_idx"); err != nil {
			return err
		}
	}

	places, err := u.hasColumn("routing_rule", "reports")
	if err != nil || places {
		return err
	}
	return u.change(routingRuleV0110(u.t), change{table: "routing_rule",
		add: []added{{column: "reports"}}})
}

// claimFromFlawV0110 gives the report written beside each flaw recorded by
// hand the flaw's summary as its claim. v0.10.0 left that report's claim
// empty and kept the summary on the issue alone, and a judged report can no
// longer be edited to fill it. Run after the issue kinds are marked, which
// is how a flaw recorded by hand is told from a published vulnerability; a
// report with a claim of its own keeps it, so a second start changes nothing.
func claimFromFlawV0110(ctx context.Context, tx bun.Tx) error {
	if _, err := tx.ExecContext(ctx, `UPDATE "flaw_report"
		SET "summary" = (SELECT "v"."description" FROM "vulnerability" AS "v"
			WHERE "v"."id" = "flaw_report"."vulnerability_id")
		WHERE ("flaw_report"."summary" IS NULL OR "flaw_report"."summary" = '')
		  AND EXISTS (SELECT 1 FROM "vulnerability" AS "v"
			WHERE "v"."id" = "flaw_report"."vulnerability_id" AND "v"."kind" = 'flaw'
			  AND "v"."description" IS NOT NULL AND "v"."description" <> '')`); err != nil {
		return fmt.Errorf("give each flaw's report its claim: %w", err)
	}
	return nil
}

// acknowledgedAsSentV0110 writes each acknowledgement v0.10.0 recorded as the
// first message sent to the reporter, dated the day it was recorded, by
// whoever recorded it, and holding no text. A report already holding a sent
// message is stepped over, so a start after one that stopped part way writes
// none twice.
//
// Read and written row by row in Go, because the day of a moment is spelled
// differently on every engine.
func acknowledgedAsSentV0110(ctx context.Context, tx bun.Tx) error {
	var rows []struct {
		ID int64     `bun:"id"`
		At time.Time `bun:"acknowledged_at"`
		By int64     `bun:"acknowledged_by"`
	}
	if err := tx.NewRaw(`SELECT "fr"."id", "fr"."acknowledged_at", "fr"."acknowledged_by"
		FROM "flaw_report" AS "fr"
		WHERE "fr"."acknowledged_at" IS NOT NULL AND "fr"."acknowledged_by" IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM "report_message" AS "rm"
			WHERE "rm"."flaw_report_id" = "fr"."id" AND "rm"."direction" = 'sent')
		ORDER BY "fr"."id"`).Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read the acknowledged reports: %w", err)
	}
	for _, row := range rows {
		at := row.At.UTC()
		day := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
		if _, err := tx.ExecContext(ctx, `INSERT INTO "report_message"
			("flaw_report_id", "direction", "dated", "logged_by", "logged_at")
			VALUES (?, 'sent', ?, ?, ?)`, row.ID, day, row.By, at); err != nil {
			return fmt.Errorf("record report %d's acknowledgement as sent: %w", row.ID, err)
		}
	}
	return nil
}

// hasForeignKey reports whether a table holds a foreign key of this name. A
// key on SQLite is part of the table and has no name the catalog answers, so
// it is asked only of the server engines.
func (u *upgrader) hasForeignKey(table, name string) (bool, error) {
	query := `SELECT 1 FROM "information_schema"."TABLE_CONSTRAINTS"
		WHERE "CONSTRAINT_SCHEMA" = DATABASE() AND "TABLE_NAME" = ? AND "CONSTRAINT_NAME" = ?
		  AND "CONSTRAINT_TYPE" = 'FOREIGN KEY' LIMIT 1`
	if u.engine == database.Postgres {
		query = `SELECT 1 FROM "information_schema"."table_constraints"
			WHERE "constraint_schema" = CURRENT_SCHEMA() AND "table_name" = ? AND "constraint_name" = ?
			  AND "constraint_type" = 'FOREIGN KEY'`
	}
	return exists(u.ctx, u.tx, fmt.Sprintf("%s has foreign key %s", table, name), query, table, name)
}

// dropForeignKey drops a foreign key ahead of dropping its column. MySQL and
// MariaDB refuse to drop a column a key names and spell the drop as a foreign
// key; PostgreSQL spells it as a constraint. SQLite rebuilds the table from a
// declaration that no longer names it.
func (u *upgrader) dropForeignKey(table, name string) error {
	if u.engine == database.SQLite {
		return nil
	}
	held, err := u.hasForeignKey(table, name)
	if err != nil || !held {
		return err
	}
	stmt := `ALTER TABLE "` + table + `" DROP FOREIGN KEY "` + name + `"`
	if u.engine == database.Postgres {
		stmt = `ALTER TABLE "` + table + `" DROP CONSTRAINT "` + name + `"`
	}
	return u.run([]string{stmt})
}
