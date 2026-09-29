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

// Upgraded, a flaw recorded here that v0.4.0 left undated under a duplicate
// ruling from outside is dated from the earliest claim from outside the
// ruling covers, and the date is recorded as a movement from that ruling. A
// claim found here, a withdrawn ruling and a flaw already dated contribute
// nothing. An issue's listing day starts empty. Rolled back, the movement goes
// and the date stays.
func duplicatesDateTheirFlaws() upgradeCheck {
	var (
		undated, dated, listed, ruling   int64
		undatedPlace, datedPlace, person int64
	)
	received := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
	already := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	want := received.Add(90 * 24 * time.Hour)
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
			earlierFoundHere := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
			earlierWithdrawn := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
			ruling = rule(undated, false,
				claim("escalation-R-2026-1", &received, false),
				claim("escalation-R-2026-2", &earlierFoundHere, true))
			rule(undated, true, claim("escalation-R-2026-3", &earlierWithdrawn, false))
			rule(dated, false, claim("escalation-R-2026-4", &earlierWithdrawn, false))
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			if got := discloseAt(t, ctx, db, undatedPlace); got == nil || !got.Equal(want) {
				t.Errorf("upgraded, the undated flaw ends %v, want %s", got, want)
			}
			if got := discloseAt(t, ctx, db, datedPlace); got == nil || !got.Equal(already) {
				t.Errorf("upgraded, the flaw already dated ends %v, want %s", got, already)
			}
			var moved []struct {
				Act    string     `bun:"act"`
				Was    *time.Time `bun:"was"`
				Until  *time.Time `bun:"until"`
				Ruling *int64     `bun:"ruling_id"`
				By     int64      `bun:"asked_by"`
			}
			if err := db.DB.NewRaw(`SELECT "act", "was", "until", "ruling_id", "asked_by"
				FROM "disclosure_movement" WHERE "vulnerability_id" IN (?, ?)`,
				undated, dated).Scan(ctx, &moved); err != nil {
				t.Fatal(err)
			}
			if len(moved) != 1 {
				t.Fatalf("upgraded, %d movements recorded, want the one", len(moved))
			}
			row := moved[0]
			if row.Act != "duplicate" || row.Was != nil || row.Until == nil ||
				!row.Until.Equal(want) || row.Ruling == nil || *row.Ruling != ruling ||
				row.By != person {
				t.Errorf("upgraded, recorded %s from %v to %v by ruling %v asked by %d, "+
					"want duplicate from none to %s by %d asked by %d",
					row.Act, row.Was, row.Until, row.Ruling, row.By, want, ruling, person)
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
			if got := discloseAt(t, ctx, db, undatedPlace); got == nil || !got.Equal(want) {
				t.Errorf("rolled back, the flaw ends %v, want the %s it was given", got, want)
			}
			if err := db.DB.NewRaw(`SELECT "exploited_on" FROM "vulnerability"`).
				Scan(ctx, new(*time.Time)); err == nil {
				t.Error("rolled back, the listing day is still there")
			}
		},
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
