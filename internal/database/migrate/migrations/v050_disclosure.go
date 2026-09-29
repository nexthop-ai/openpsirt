// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// disclosureMovementV050 is v0.5.0's declaration of the record of every time
// an embargo's end moved.
//
// v0.2.0's, which v0.3.0 and v0.4.0 left as it was, with the ruling that
// recorded a movement and the claim its date counts from, and both dates able
// to be absent where a ruling recorded it.
func disclosureMovementV050(t *columnTypes) []string {
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

// movementsFromRulings upgrades the record of embargo movements to hold the
// ones a ruling records, and gives each flaw recorded here the disclosure date
// its duplicates from outside start.
//
// v0.4.0 dated nothing from a duplicate ruling. A flaw still undisclosed and
// open in a product, with no date on any of its places there, takes the date
// each duplicate ruling in force would have given it: when the earliest claim
// from outside the ruling covers arrived, or was recorded where it does not
// say, plus the disclosure window. The rulings are taken in the order they took
// effect, and each one moving the date earlier is recorded as a movement from
// that ruling, as a ruling made after the upgrade is. A flaw with a date on any
// place is left as it is, because an end already set is one somebody is held
// to.
func movementsFromRulings(ctx context.Context, u *upgrader) error {
	if err := u.change(disclosureMovementV050(u.t), change{table: "disclosure_movement",
		add:         []added{{column: "ruling_id"}, {column: "flaw_report_id"}},
		relax:       []string{"was", "until"},
		constraints: []string{"disclosure_movement_ruling_fk", "disclosure_movement_report_fk"},
	}); err != nil {
		return err
	}
	return datedFromDuplicates(ctx, u.tx)
}

// v0.4.0's name for the disclosure window and its default. Spelled here rather
// than read from the settings package, because this migration upgrades what
// v0.4.0 stored and a later rename there must not change what it does.
const (
	v040DiscloseAfter        = "disclosure.after"
	v040DefaultDiscloseAfter = 90 * 24 * time.Hour
)

// datedFromDuplicates writes the dates v0.4.0's duplicate rulings would have
// started, and the movements recording them.
func datedFromDuplicates(ctx context.Context, tx bun.Tx) error {
	window := v040DefaultDiscloseAfter
	var stored []string
	if err := tx.NewRaw(`SELECT "value" FROM "application_setting" WHERE "name" = ?`,
		v040DiscloseAfter).Scan(ctx, &stored); err != nil {
		return fmt.Errorf("read the disclosure window: %w", err)
	}
	if len(stored) > 0 {
		if parsed, err := time.ParseDuration(stored[0]); err == nil && parsed > 0 {
			window = parsed
		}
	}

	var rulings []struct {
		ID         int64          `bun:"id"`
		ProductID  int64          `bun:"product_id"`
		Issue      int64          `bun:"duplicate_of"`
		Reasoning  sql.NullString `bun:"reasoning"`
		ProposedBy int64          `bun:"proposed_by"`
		SettledAt  time.Time      `bun:"settled_at"`
	}
	if err := tx.NewRaw(`SELECT "id", "product_id", "duplicate_of", "reasoning",
			"proposed_by", "settled_at"
		FROM "report_ruling"
		WHERE "disposition" = ? AND "duplicate_of" IS NOT NULL
		  AND "settled_at" IS NOT NULL AND "withdrawn_at" IS NULL
		ORDER BY "settled_at", "id"`, "duplicate").Scan(ctx, &rulings); err != nil {
		return fmt.Errorf("read the duplicate rulings in force: %w", err)
	}

	type flaw struct{ product, issue int64 }
	ends := map[flaw]*time.Time{}
	undated := map[flaw]bool{}
	for _, ruling := range rulings {
		var claims []struct {
			ID         int64      `bun:"id"`
			ReceivedOn *time.Time `bun:"received_on"`
			RecordedAt time.Time  `bun:"recorded_at"`
		}
		if err := tx.NewRaw(`SELECT "fr"."id" AS "id", "fr"."received_on" AS "received_on",
				"fr"."recorded_at" AS "recorded_at"
			FROM "report_ruled" AS "rd"
			JOIN "flaw_report" AS "fr" ON "fr"."id" = "rd"."flaw_report_id"
			WHERE "rd"."ruling_id" = ? AND "fr"."found_here" = ?
			ORDER BY "fr"."id"`, ruling.ID, false).Scan(ctx, &claims); err != nil {
			return fmt.Errorf("read when a duplicate's claims arrived: %w", err)
		}
		var from *time.Time
		var report int64
		for _, claim := range claims {
			arrived := claim.RecordedAt
			if claim.ReceivedOn != nil {
				arrived = *claim.ReceivedOn
			}
			arrived = arrived.UTC()
			if from == nil || arrived.Before(*from) {
				from, report = &arrived, claim.ID
			}
		}
		if from == nil {
			continue
		}
		at := from.Add(window).Truncate(time.Microsecond)

		var places []struct {
			ID         int64      `bun:"id"`
			DiscloseAt *time.Time `bun:"disclose_at"`
		}
		if err := tx.NewRaw(`SELECT "f"."id" AS "id", "f"."disclose_at" AS "disclose_at"
			FROM "finding" AS "f"
			JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"
			JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"
			WHERE "f"."vulnerability_id" = ? AND "st"."product_id" = ?
			  AND "f"."kind" = ? AND "f"."visibility" = ? AND "f"."closed_at" IS NULL`,
			ruling.Issue, ruling.ProductID, "entered", "private").Scan(ctx, &places); err != nil {
			return fmt.Errorf("read a duplicated flaw's places: %w", err)
		}
		if len(places) == 0 {
			continue
		}
		key := flaw{ruling.ProductID, ruling.Issue}
		if _, seen := undated[key]; !seen {
			none := true
			for _, place := range places {
				none = none && place.DiscloseAt == nil
			}
			undated[key] = none
		}
		if !undated[key] {
			continue
		}
		was := ends[key]
		if was != nil && !at.Before(*was) {
			continue
		}
		ids := make([]int64, 0, len(places))
		for _, place := range places {
			ids = append(ids, place.ID)
		}
		if err := inBatches(ctx, ids, func(batch []int64) error {
			_, err := tx.NewRaw(`UPDATE "finding" SET "disclose_at" = ? WHERE "id" IN (?)`,
				at, bun.List(batch)).Exec(ctx)
			return err
		}); err != nil {
			return fmt.Errorf("date a duplicated flaw: %w", err)
		}
		if _, err := tx.NewRaw(`INSERT INTO "disclosure_movement"
			("vulnerability_id", "product_id", "act", "was", "until", "reason",
			 "asked_by", "asked_at", "needs_approval", "ruling_id", "flaw_report_id")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			ruling.Issue, ruling.ProductID, "duplicate", was, at, ruling.Reasoning.String,
			ruling.ProposedBy, ruling.SettledAt, false, ruling.ID, report).Exec(ctx); err != nil {
			return fmt.Errorf("record the date a duplicate started: %w", err)
		}
		dated := at
		ends[key] = &dated
	}
	return nil
}

// movementsNarrowed puts back the record of embargo movements v0.4.0 built.
//
// A movement a ruling recorded goes, because v0.4.0 has no place for an act
// nobody asked for. The dates it set stay on the flaw's places, which v0.4.0
// reads as an end like any other.
func (u *upgrader) movementsNarrowed() error {
	movements := narrowing{table: "disclosure_movement",
		forget:  `DELETE FROM "disclosure_movement" WHERE "ruling_id" IS NOT NULL`,
		keys:    []string{"disclosure_movement_ruling_fk", "disclosure_movement_report_fk"},
		columns: []string{"ruling_id", "flaw_report_id"}}
	if u.engine == database.SQLite {
		movements.require = []string{"was", "until"}
		return u.narrow(movements)
	}
	if err := u.narrow(movements); err != nil {
		return err
	}
	if u.engine == database.Postgres {
		return u.run([]string{
			`ALTER TABLE "disclosure_movement" ALTER COLUMN "was" SET NOT NULL`,
			`ALTER TABLE "disclosure_movement" ALTER COLUMN "until" SET NOT NULL`,
		})
	}
	made, _, err := pick(disclosureMovementV050(u.t), "disclosure_movement")
	if err != nil {
		return err
	}
	items, err := declared(made)
	if err != nil {
		return err
	}
	var stmts []string
	for _, column := range []string{"was", "until"} {
		def, err := items.column(column)
		if err != nil {
			return err
		}
		stmts = append(stmts, `ALTER TABLE "disclosure_movement" MODIFY COLUMN `+refusingNull(def))
	}
	return u.run(stmts)
}
