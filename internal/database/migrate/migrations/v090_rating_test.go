// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// A v0.8.0 database holding a recorded flaw's rating on the issue row is
// upgraded: the word, the score, the vector and its scheme are the recording
// product's, the word is in force there, the issue holds none of them, and a
// rating a feed published beside them stays. A scanned issue that absorbed a
// record keeps its scanner's word and score, and gives up what the merge
// copied from the record. A record filed under a published name and scanned
// elsewhere gives up its word, records its own unsourced rating, and keeps a
// feed's sourced score.
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
		place := func(kind string, issue int64, identity string) {
			t.Helper()
			exec(`INSERT INTO "finding" ("target_id", "kind", "visibility", "vulnerability_id", "component_id",
				"place_identity", "urgency", "urgency_exploited", "urgency_exploited_here",
				"urgency_shipped", "last_changed_at", "opened_at")
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				declared.Target.ID, kind, "private", issue, component, identity, 1, false, false, true, at, at)
		}
		place("entered", issue, "swss")
		rated := func(identifier, severity string, score int, source string) int64 {
			t.Helper()
			exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "severity", "exploited",
				"score_centi", "score_source", "first_seen_at", "issue_id")
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				identifier, strings.ToLower(identifier), severity, false, score, source, at, 0)
			id := id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, identifier)
			exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, id)
			return id
		}

		// A scanned issue that absorbed a record in a merge: its word and its
		// unsourced score are the scanner's, and stay.
		kept := rated("CVE-2026-0002", "high", 750, "")
		absorbed := rated("SONIC-2026-0002", "low", 200, "")
		exec(`UPDATE "vulnerability" SET "issue_id" = ? WHERE "id" = ?`, kept, absorbed)
		exec(`INSERT INTO "vulnerability_merge" ("absorbed_id", "kept_id", "named", "merged_at")
			VALUES (?, ?, ?, ?)`, absorbed, kept, "CVE-2026-0002 SONIC-2026-0002", at)
		place("vulnerability", kept, "swss-scanned")
		place("entered", kept, "swss-entered")

		// A scanned issue that absorbed a record whose word, score and
		// rating the merge copied onto it: those are the record's.
		copied := rated("CVE-2026-0004", "critical", 980, "")
		exec(`UPDATE "vulnerability" SET "vector" = ? WHERE "id" = ?`, vector, copied)
		copiedFrom := rated("SONIC-2026-0004", "critical", 980, "")
		exec(`UPDATE "vulnerability" SET "vector" = ?, "issue_id" = ? WHERE "id" = ?`, vector, copied, copiedFrom)
		exec(`INSERT INTO "vulnerability_merge" ("absorbed_id", "kept_id", "named", "merged_at")
			VALUES (?, ?, ?, ?)`, copiedFrom, copied, "CVE-2026-0004 SONIC-2026-0004", at)
		exec(`INSERT INTO "vulnerability_rating" ("vulnerability_id", "generation", "score_centi", "vector")
			VALUES (?, ?, ?, ?)`, copied, 3, 980, vector)
		place("vulnerability", copied, "swss-copied-scanned")
		place("entered", copied, "swss-copied-entered")

		// A record filed under a published name, scanned elsewhere, that a
		// feed later scored on a newer scheme: the word is the record's, its
		// own unsourced rating is its score, and the feed's score stays.
		refiled := rated("CVE-2026-0003", "critical", 880, "nvd@nist.gov")
		exec(`INSERT INTO "vulnerability_rating" ("vulnerability_id", "generation", "score_centi", "vector")
			VALUES (?, ?, ?, ?)`, refiled, 3, 980, vector)
		exec(`INSERT INTO "vulnerability_rating" ("vulnerability_id", "generation", "score_centi", "vector", "score_source")
			VALUES (?, ?, ?, ?, ?)`, refiled, 4, 880, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "nvd@nist.gov")
		place("entered", refiled, "swss-refiled")
		place("vulnerability", refiled, "swss-refiled-scanned")

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

		var merged struct {
			Severity   *string `bun:"severity"`
			ScoreCenti *int64  `bun:"score_centi"`
		}
		if err := db.DB.NewRaw(`SELECT "severity", "score_centi" FROM "vulnerability" WHERE "id" = ?`,
			kept).Scan(ctx, &merged); err != nil {
			t.Fatal(err)
		}
		if merged.Severity == nil || *merged.Severity != "high" || merged.ScoreCenti == nil || *merged.ScoreCenti != 750 {
			t.Errorf("the merged issue reads %+v, want the scanner's high and 7.50", merged)
		}
		if moved := id(`SELECT COUNT(*) FROM "recorded_rating" WHERE "vulnerability_id" = ?`, kept); moved != 0 {
			t.Errorf("the scanner's rating of a merged issue was recorded as a product's %d times", moved)
		}

		var fromRecord struct {
			Severity   *string `bun:"severity"`
			ScoreCenti *int64  `bun:"score_centi"`
		}
		if err := db.DB.NewRaw(`SELECT "severity", "score_centi" FROM "recorded_rating" WHERE "vulnerability_id" = ?`,
			refiled).Scan(ctx, &fromRecord); err != nil {
			t.Fatal(err)
		}
		if fromRecord.Severity == nil || *fromRecord.Severity != "critical" ||
			fromRecord.ScoreCenti == nil || *fromRecord.ScoreCenti != 980 {
			t.Errorf("the refiled record's rating reads %+v, want its word critical and its own 9.80", fromRecord)
		}
		if left := id(`SELECT COUNT(*) FROM "vulnerability_rating" WHERE "vulnerability_id" = ?`, refiled); left != 1 {
			t.Errorf("%d ratings are left on the refiled issue, want the feed's", left)
		}

		var copiedRecord struct {
			Severity   *string `bun:"severity"`
			ScoreCenti *int64  `bun:"score_centi"`
		}
		if err := db.DB.NewRaw(`SELECT "severity", "score_centi" FROM "recorded_rating" WHERE "vulnerability_id" = ?`,
			copied).Scan(ctx, &copiedRecord); err != nil {
			t.Fatal(err)
		}
		if copiedRecord.Severity == nil || *copiedRecord.Severity != "critical" ||
			copiedRecord.ScoreCenti == nil || *copiedRecord.ScoreCenti != 980 {
			t.Errorf("what a merge copied reads %+v as recorded, want critical and 9.80", copiedRecord)
		}
		var copiedRow struct {
			Severity   *string `bun:"severity"`
			ScoreCenti *int64  `bun:"score_centi"`
		}
		if err := db.DB.NewRaw(`SELECT "severity", "score_centi" FROM "vulnerability" WHERE "id" = ?`,
			copied).Scan(ctx, &copiedRow); err != nil {
			t.Fatal(err)
		}
		if copiedRow.Severity != nil || copiedRow.ScoreCenti != nil {
			t.Errorf("the issue a merge copied a record onto still reads %+v", copiedRow)
		}
		if left := id(`SELECT COUNT(*) FROM "vulnerability_rating" WHERE "vulnerability_id" = ?`, copied); left != 0 {
			t.Errorf("%d of the record's ratings are left on the issue a merge copied it onto", left)
		}
		var refiledRow struct {
			Severity   *string `bun:"severity"`
			ScoreCenti *int64  `bun:"score_centi"`
		}
		if err := db.DB.NewRaw(`SELECT "severity", "score_centi" FROM "vulnerability" WHERE "id" = ?`,
			refiled).Scan(ctx, &refiledRow); err != nil {
			t.Fatal(err)
		}
		if refiledRow.Severity != nil || refiledRow.ScoreCenti == nil || *refiledRow.ScoreCenti != 880 {
			t.Errorf("the refiled issue reads %+v, want no word and the feed's 8.80", refiledRow)
		}
	})
}
