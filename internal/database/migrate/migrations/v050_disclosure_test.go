// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Upgraded, a flaw recorded here that v0.4.0 left undated under duplicate
// rulings from outside is dated by them in the order they took effect: the
// first gives the date, one bringing it in within the threshold moves it, and
// one bringing it in past the threshold is recorded waiting for a second
// person. Each is a movement from its ruling. A claim found here, a withdrawn
// ruling and a flaw already dated contribute nothing. An issue's listing day
// starts empty. Rolled back, the movements go and the date stays; upgraded
// again, the same movements are recorded and the date is the same.
func duplicatesDateTheirFlaws() upgradeCheck {
	var (
		undated, dated, listed           int64
		undatedPlace, datedPlace, person int64
		first, within, past              int64
	)
	day := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }
	window := 90 * 24 * time.Hour
	already := day(2026, 6, 1)
	firstAt := day(2026, 1, 10).Add(window)
	withinAt := day(2026, 1, 1).Add(window)
	pastAt := day(2025, 12, 1).Add(window)
	return upgradeCheck{
		name: "AnUpgradeDatesAFlawItsDuplicatesFromOutsideLeftUndated",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			cat := catalog.NewStore(db.DB)
			product, err := cat.DeclareProduct(ctx, "escalation", "Escalation")
			if err != nil {
				t.Fatal(err)
			}
			stream, err := cat.DeclareStream(ctx, product.ID, "main", catalog.Branch, nil)
			if err != nil {
				t.Fatal(err)
			}
			variant, err := cat.DeclareVariant(ctx, product.ID, "base", true)
			if err != nil {
				t.Fatal(err)
			}
			target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
			if err != nil {
				t.Fatal(err)
			}
			ruler, err := access.NewStore(db.DB).Ensure(ctx, "ruler", "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			person = ruler.ID
			now := time.Now().UTC().Truncate(time.Second)

			widget := graph.Described{Name: "escalation-widget", Version: "1.0"}
			exec(t, ctx, db, `INSERT INTO "component" ("identity", "name", "version", "fold_key",
				"first_seen_at") VALUES (?, ?, ?, ?, ?)`,
				"escalation-widget-v040", widget.Name, widget.Version, widget.FoldKey(), now)
			var component int64
			if err := db.DB.NewRaw(`SELECT "id" FROM "component" WHERE "identity" = ?`,
				"escalation-widget-v040").Scan(ctx, &component); err != nil {
				t.Fatal(err)
			}

			undated = insertIssue(t, ctx, db, "OPENPSIRT-2026-0701")
			dated = insertIssue(t, ctx, db, "OPENPSIRT-2026-0702")
			listed = insertIssue(t, ctx, db, "CVE-2026-0703")
			exec(t, ctx, db, `UPDATE "vulnerability" SET "exploited" = ? WHERE "id" = ?`, true, listed)

			place := func(issue int64, disclose *time.Time) int64 {
				exec(t, ctx, db, `INSERT INTO "finding" ("target_id", "kind", "visibility",
					"vulnerability_id", "component_id", "place_identity", "opened_at",
					"last_changed_at", "urgency", "urgency_exploited", "urgency_exploited_here",
					"urgency_shipped", "disclose_at")
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					target.ID, "entered", "private", issue, component, "escalation-widget",
					now, now, 0, false, false, true, disclose)
				var id int64
				if err := db.DB.NewRaw(`SELECT "id" FROM "finding" WHERE "vulnerability_id" = ?`,
					issue).Scan(ctx, &id); err != nil {
					t.Fatal(err)
				}
				return id
			}
			undatedPlace = place(undated, nil)
			datedPlace = place(dated, &already)

			claim := func(reference string, on *time.Time, foundHere bool) int64 {
				exec(t, ctx, db, `INSERT INTO "flaw_report" ("product_id", "reference",
					"received_on", "found_here", "recorded_by", "recorded_at")
					VALUES (?, ?, ?, ?, ?, ?)`,
					product.ID, reference, on, foundHere, person, now)
				var id int64
				if err := db.DB.NewRaw(`SELECT "id" FROM "flaw_report" WHERE "reference" = ?`,
					reference).Scan(ctx, &id); err != nil {
					t.Fatal(err)
				}
				return id
			}
			rule := func(issue int64, withdrawn bool, claims ...int64) int64 {
				var gone any
				if withdrawn {
					gone = now
				}
				exec(t, ctx, db, `INSERT INTO "report_ruling" ("product_id", "disposition",
					"duplicate_of", "proposed_by", "proposed_at", "settled_at", "withdrawn_at")
					VALUES (?, ?, ?, ?, ?, ?, ?)`,
					product.ID, "duplicate", issue, person, now, now, gone)
				var id int64
				if err := db.DB.NewRaw(`SELECT MAX("id") FROM "report_ruling"`).Scan(ctx, &id); err != nil {
					t.Fatal(err)
				}
				for _, each := range claims {
					exec(t, ctx, db, `INSERT INTO "report_ruled" ("ruling_id", "flaw_report_id")
						VALUES (?, ?)`, id, each)
				}
				return id
			}
			received := func(d time.Time) *time.Time { return &d }
			first = rule(undated, false,
				claim("escalation-R-2026-1", received(day(2026, 1, 10)), false),
				claim("escalation-R-2026-2", received(day(2025, 10, 1)), true))
			rule(undated, true, claim("escalation-R-2026-3", received(day(2025, 11, 1)), false))
			within = rule(undated, false, claim("escalation-R-2026-5", received(day(2026, 1, 1)), false))
			past = rule(undated, false, claim("escalation-R-2026-6", received(day(2025, 12, 1)), false))
			rule(dated, false, claim("escalation-R-2026-4", received(day(2025, 11, 1)), false))
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			datedByRulings(t, ctx, db, "upgraded", undated, undatedPlace, withinAt, person,
				[]movedByRuling{{first, nil, firstAt, false}, {within, &firstAt, withinAt, false},
					{past, &withinAt, pastAt, true}})
			if got := discloseAt(t, ctx, db, datedPlace); got == nil || !got.Equal(already) {
				t.Errorf("upgraded, the flaw already dated ends %v, want %s", got, already)
			}
			var moved int
			if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "disclosure_movement" WHERE "vulnerability_id" = ?`,
				dated).Scan(ctx, &moved); err != nil {
				t.Fatal(err)
			}
			if moved != 0 {
				t.Errorf("upgraded, the flaw already dated gained %d movements", moved)
			}
			var on *time.Time
			if err := db.DB.NewRaw(`SELECT "exploited_on" FROM "vulnerability" WHERE "id" = ?`,
				listed).Scan(ctx, &on); err != nil {
				t.Fatal(err)
			}
			if on != nil {
				t.Errorf("upgraded, an exploited issue reads as listed on %s", on)
			}
		},
		rolledBack: func(t *testing.T, ctx context.Context, db *database.DB) {
			var left int
			if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "disclosure_movement"
				WHERE "vulnerability_id" = ?`, undated).Scan(ctx, &left); err != nil {
				t.Fatal(err)
			}
			if left != 0 {
				t.Errorf("rolled back, %d movements a ruling recorded remain", left)
			}
			if got := discloseAt(t, ctx, db, undatedPlace); got == nil || !got.Equal(withinAt) {
				t.Errorf("rolled back, the flaw ends %v, want the %s it was given", got, withinAt)
			}
			if err := db.DB.NewRaw(`SELECT "exploited_on" FROM "vulnerability"`).
				Scan(ctx, new(*time.Time)); err == nil {
				t.Error("rolled back, the listing day is still there")
			}
		},
		upgradedAgain: func(t *testing.T, ctx context.Context, db *database.DB) {
			datedByRulings(t, ctx, db, "upgraded again", undated, undatedPlace, withinAt, person,
				[]movedByRuling{{first, nil, firstAt, false}, {within, &firstAt, withinAt, false},
					{past, &withinAt, pastAt, true}})
		},
	}
}

// movedByRuling is a movement a ruling recorded, as a check expects it.
type movedByRuling struct {
	ruling int64
	was    *time.Time
	until  time.Time
	waits  bool
}

// datedByRulings checks a flaw's date and the movements its rulings recorded,
// in order.
func datedByRulings(t *testing.T, ctx context.Context, db *database.DB, step string,
	issue, place int64, ends time.Time, person int64, want []movedByRuling) {

	t.Helper()
	if got := discloseAt(t, ctx, db, place); got == nil || !got.Equal(ends) {
		t.Errorf("%s, the flaw ends %v, want %s", step, got, ends)
	}
	var moved []struct {
		Act    string     `bun:"act"`
		Was    *time.Time `bun:"was"`
		Until  *time.Time `bun:"until"`
		Ruling *int64     `bun:"ruling_id"`
		By     int64      `bun:"asked_by"`
		Waits  bool       `bun:"needs_approval"`
	}
	if err := db.DB.NewRaw(`SELECT "act", "was", "until", "ruling_id", "asked_by", "needs_approval"
		FROM "disclosure_movement" WHERE "vulnerability_id" = ? ORDER BY "id"`,
		issue).Scan(ctx, &moved); err != nil {
		t.Fatal(err)
	}
	if len(moved) != len(want) {
		t.Fatalf("%s, %d movements recorded, want %d", step, len(moved), len(want))
	}
	for i, row := range moved {
		w := want[i]
		sameWas := (row.Was == nil && w.was == nil) || (row.Was != nil && w.was != nil && row.Was.Equal(*w.was))
		if row.Act != "duplicate" || !sameWas || row.Until == nil || !row.Until.Equal(w.until) ||
			row.Ruling == nil || *row.Ruling != w.ruling || row.By != person || row.Waits != w.waits {
			t.Errorf("%s, movement %d is %s from %v to %v by ruling %v asked by %d waiting %v, "+
				"want duplicate from %v to %s by %d asked by %d waiting %v", step, i,
				row.Act, row.Was, row.Until, row.Ruling, row.By, row.Waits,
				w.was, w.until, w.ruling, person, w.waits)
		}
	}
}

// discloseAt reads the disclosure date one finding holds.
func discloseAt(t *testing.T, ctx context.Context, db *database.DB, id int64) *time.Time {
	t.Helper()
	var at *time.Time
	if err := db.DB.NewRaw(`SELECT "disclose_at" FROM "finding" WHERE "id" = ?`, id).
		Scan(ctx, &at); err != nil {
		t.Fatal(err)
	}
	return at
}
