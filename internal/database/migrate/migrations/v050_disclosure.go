// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/uptrace/bun"
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
// v0.4.0 dated nothing from a duplicate ruling. For a flaw still undisclosed
// and open in a product, each duplicate ruling in force is taken in the order
// it took effect, as a ruling made after the upgrade is: its date is when the
// earliest claim from outside it covers arrived, or was recorded where it does
// not say, plus the disclosure window. The first gives the flaw its date and
// needs nobody. A later one bringing the date earlier is a shortening: past the
// movement threshold it is recorded waiting for a second person and moves
// nothing. Each is a movement from its ruling.
//
// A flaw with a date on a place is left as it is, because an end already set
// is one somebody is held to — except where every place holds exactly the date
// its rulings give. That is the date an earlier run of this upgrade wrote and
// a roll back kept, and the movements naming the rulings are recorded again.
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

// v0.4.0's names for the disclosure window and the movement threshold, and
// their defaults. Spelled here rather than read from the settings package,
// because this migration upgrades what v0.4.0 stored and a later rename there
// must not change what it does.
const (
	v040DiscloseAfter            = "disclosure.after"
	v040DefaultDiscloseAfter     = 90 * 24 * time.Hour
	v040MovementThreshold        = "disclosure.movement-threshold"
	v040DefaultMovementThreshold = 30 * 24 * time.Hour
)

// v040Duration reads a duration v0.4.0 stored, falling back where it is unset
// or unreadable, as v0.4.0 read it.
func v040Duration(ctx context.Context, tx bun.Tx, name string, fallback time.Duration) (time.Duration, error) {
	var stored []string
	if err := tx.NewRaw(`SELECT "value" FROM "application_setting" WHERE "name" = ?`,
		name).Scan(ctx, &stored); err != nil {
		return 0, fmt.Errorf("read %s: %w", name, err)
	}
	if len(stored) > 0 {
		if parsed, err := time.ParseDuration(stored[0]); err == nil && parsed > 0 {
			return parsed, nil
		}
	}
	return fallback, nil
}

// dupRuling is one duplicate ruling in force, and the date it gives.
type dupRuling struct {
	ID         int64          `bun:"id"`
	ProductID  int64          `bun:"product_id"`
	Issue      int64          `bun:"duplicate_of"`
	Reasoning  sql.NullString `bun:"reasoning"`
	ProposedBy int64          `bun:"proposed_by"`
	SettledAt  time.Time      `bun:"settled_at"`

	at     time.Time
	report int64
}

// dupStep is one movement a ruling records.
type dupStep struct {
	ruling dupRuling
	was    *time.Time
	waits  bool
}

// dupChain is what a flaw's rulings record, in order, and where they leave its
// date.
func dupChain(rulings []dupRuling, threshold time.Duration) ([]dupStep, *time.Time) {
	var steps []dupStep
	var ends *time.Time
	var already time.Duration
	for _, ruling := range rulings {
		if ends != nil && !ruling.at.Before(*ends) {
			continue
		}
		step := dupStep{ruling: ruling, was: ends}
		if ends != nil {
			distance := ends.Sub(ruling.at)
			step.waits = already+distance >= threshold
			if !step.waits {
				already += distance
			}
		}
		steps = append(steps, step)
		if !step.waits {
			at := ruling.at
			ends = &at
		}
	}
	return steps, ends
}

// datedFromDuplicates writes the dates v0.4.0's duplicate rulings would have
// started, and the movements recording them.
func datedFromDuplicates(ctx context.Context, tx bun.Tx) error {
	window, err := v040Duration(ctx, tx, v040DiscloseAfter, v040DefaultDiscloseAfter)
	if err != nil {
		return err
	}
	threshold, err := v040Duration(ctx, tx, v040MovementThreshold, v040DefaultMovementThreshold)
	if err != nil {
		return err
	}

	var rulings []dupRuling
	if err := tx.NewRaw(`SELECT "id", "product_id", "duplicate_of", "reasoning",
			"proposed_by", "settled_at"
		FROM "report_ruling"
		WHERE "disposition" = ? AND "duplicate_of" IS NOT NULL
		  AND "settled_at" IS NOT NULL AND "withdrawn_at" IS NULL
		ORDER BY "settled_at", "id"`, "duplicate").Scan(ctx, &rulings); err != nil {
		return fmt.Errorf("read the duplicate rulings in force: %w", err)
	}

	type flaw struct{ product, issue int64 }
	var order []flaw
	byFlaw := map[flaw][]dupRuling{}
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
		for _, claim := range claims {
			arrived := claim.RecordedAt
			if claim.ReceivedOn != nil {
				arrived = *claim.ReceivedOn
			}
			arrived = arrived.UTC()
			if from == nil || arrived.Before(*from) {
				from, ruling.report = &arrived, claim.ID
			}
		}
		if from == nil {
			continue
		}
		ruling.at = from.Add(window).Truncate(time.Microsecond)
		key := flaw{ruling.ProductID, ruling.Issue}
		if _, seen := byFlaw[key]; !seen {
			order = append(order, key)
		}
		byFlaw[key] = append(byFlaw[key], ruling)
	}

	for _, key := range order {
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
			key.issue, key.product, "entered", "private").Scan(ctx, &places); err != nil {
			return fmt.Errorf("read a duplicated flaw's places: %w", err)
		}
		if len(places) == 0 {
			continue
		}
		steps, ends := dupChain(byFlaw[key], threshold)
		undated, given := true, ends != nil
		for _, place := range places {
			undated = undated && place.DiscloseAt == nil
			given = given && place.DiscloseAt != nil && place.DiscloseAt.Equal(*ends)
		}
		if !undated && !given {
			continue
		}
		if ends != nil {
			ids := make([]int64, 0, len(places))
			for _, place := range places {
				ids = append(ids, place.ID)
			}
			if err := inBatches(ctx, ids, func(batch []int64) error {
				_, err := tx.NewRaw(`UPDATE "finding" SET "disclose_at" = ? WHERE "id" IN (?)`,
					*ends, bun.List(batch)).Exec(ctx)
				return err
			}); err != nil {
				return fmt.Errorf("date a duplicated flaw: %w", err)
			}
		}
		for _, step := range steps {
			ruling := step.ruling
			if _, err := tx.NewRaw(`INSERT INTO "disclosure_movement"
				("vulnerability_id", "product_id", "act", "was", "until", "reason",
				 "asked_by", "asked_at", "needs_approval", "ruling_id", "flaw_report_id")
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				ruling.Issue, ruling.ProductID, "duplicate", step.was, ruling.at,
				ruling.Reasoning.String, ruling.ProposedBy, ruling.SettledAt, step.waits,
				ruling.ID, ruling.report).Exec(ctx); err != nil {
				return fmt.Errorf("record the date a duplicate started: %w", err)
			}
		}
	}
	return nil
}

// movementsNarrowed puts back the record of embargo movements v0.4.0 built.
//
// A movement a ruling recorded goes, because v0.4.0 has no place for an act
// nobody asked for. The dates it set stay on the flaw's places, which v0.4.0
// reads as an end like any other.
func (u *upgrader) movementsNarrowed() error {
	return u.narrowRequiring(narrowing{table: "disclosure_movement",
		forget:  `DELETE FROM "disclosure_movement" WHERE "ruling_id" IS NOT NULL`,
		keys:    []string{"disclosure_movement_ruling_fk", "disclosure_movement_report_fk"},
		columns: []string{"ruling_id", "flaw_report_id"}},
		disclosureMovementV050(u.t), "was", "until")
}
