// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// A v0.8.0 database holding a recorded flaw's rating on the issue row is
// upgraded: the word, the score, the vector and its scheme are the recording
// product's, the word is in force there, the issue holds none of them, and a
// rating a feed published beside them stays.
func TestAV080RecordedRatingMovesToTheProductThatRecordedIt(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v080)
		declared, err := world.Declare(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}
		id := func(query string, args ...any) int64 {
			t.Helper()
			var out int64
			if err := db.DB.NewRaw(query, args...).Scan(ctx, &out); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
			return out
		}
		exec(`INSERT INTO "component" ("identity", "name", "version", "name_folded", "fold_key", "first_seen_at")
			VALUES (?, ?, ?, ?, ?, ?)`, "swss@1", "swss", "1", "swss", "swss@1", at)
		component := id(`SELECT "id" FROM "component" WHERE "identity" = ?`, "swss@1")
		const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
		exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "severity", "exploited",
			"score_centi", "vector", "score_version", "first_seen_at", "issue_id")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			"SONIC-2026-0001", "sonic-2026-0001", "critical", false, 980, vector, "3.1", at, 0)
		issue := id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "SONIC-2026-0001")
		exec(`UPDATE "vulnerability" SET "issue_id" = "id"`)
		exec(`INSERT INTO "vulnerability_rating" ("vulnerability_id", "generation", "score_centi", "vector")
			VALUES (?, ?, ?, ?)`, issue, 3, 980, vector)
		exec(`INSERT INTO "vulnerability_rating" ("vulnerability_id", "generation", "score_centi", "vector", "score_source")
			VALUES (?, ?, ?, ?, ?)`, issue, 2, 750, "AV:N/AC:L/Au:N/C:P/I:P/A:P", "nvd@nist.gov")
		exec(`INSERT INTO "finding" ("target_id", "kind", "visibility", "vulnerability_id", "component_id",
			"place_identity", "urgency", "urgency_exploited", "urgency_exploited_here",
			"urgency_shipped", "last_changed_at", "opened_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			declared.Target.ID, "entered", "private", issue, component, "swss", 1, false, false, true, at, at)

		dbtest.MigrateTo(t, db, v090)

		var recorded []struct {
			ProductID    int64   `bun:"product_id"`
			Severity     *string `bun:"severity"`
			ScoreCenti   *int64  `bun:"score_centi"`
			Vector       *string `bun:"vector"`
			ScoreVersion *string `bun:"score_version"`
		}
		if err := db.DB.NewRaw(`SELECT "product_id", "severity", "score_centi", "vector", "score_version"
			FROM "recorded_rating" WHERE "vulnerability_id" = ?`, issue).Scan(ctx, &recorded); err != nil {
			t.Fatal(err)
		}
		if len(recorded) != 1 || recorded[0].ProductID != declared.Product.ID ||
			recorded[0].Severity == nil || *recorded[0].Severity != "critical" ||
			recorded[0].ScoreCenti == nil || *recorded[0].ScoreCenti != 980 ||
			recorded[0].Vector == nil || *recorded[0].Vector != vector ||
			recorded[0].ScoreVersion == nil || *recorded[0].ScoreVersion != "3.1" {
			t.Fatalf("the recorded rating reads %+v", recorded)
		}
		if inForce := id(`SELECT COUNT(*) FROM "issue_rating"
			WHERE "vulnerability_id" = ? AND "product_id" = ? AND "severity" = ?`,
			issue, declared.Product.ID, "critical"); inForce != 1 {
			t.Errorf("the recorded word is in force in %d rows, want 1", inForce)
		}
		var row struct {
			Severity   *string `bun:"severity"`
			ScoreCenti *int64  `bun:"score_centi"`
			Vector     *string `bun:"vector"`
		}
		if err := db.DB.NewRaw(`SELECT "severity", "score_centi", "vector" FROM "vulnerability" WHERE "id" = ?`,
			issue).Scan(ctx, &row); err != nil {
			t.Fatal(err)
		}
		if row.Severity != nil || row.ScoreCenti != nil || row.Vector != nil {
			t.Errorf("the issue row still holds the recorded rating: %+v", row)
		}
		if left := id(`SELECT COUNT(*) FROM "vulnerability_rating" WHERE "vulnerability_id" = ?`, issue); left != 1 {
			t.Errorf("%d ratings are left on the issue, want the one a feed published", left)
		}
	})
}
