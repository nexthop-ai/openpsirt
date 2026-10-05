// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// v060 is the migration the untagged release carries v0.5.0's schema across
// with.
const v060 = 40

// A v0.5.0 database holding a window and a notice is upgraded, rolled back and
// upgraded again. Upgraded, the window counts from the moment the attack
// became known rather than from a notice or a fix, the notice says none of
// what a notice may now carry, and the record names no fix release. Rolled
// back, both are still there and what v0.5.0 cannot hold is gone.
func TestAV050DatabaseUpgradesToTheUntaggedReleaseAndBack(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v050)
		window, notice := seedV050Obligation(t, ctx, db)
		// A group mapped as v0.5.0 mapped one, against the product's row, and
		// one mapped to administration.
		if _, err := db.DB.NewRaw(`INSERT INTO "group_role" ("group_name", "product_id", "role", "created_at")`+
			` SELECT ?, "id", ?, "created_at" FROM "product"`, "kernel", "public-read").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "group_admin" ("group_name", "grants", "created_at")`+
			` VALUES (?, ?, ?)`, "leads", "admin", time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		dbtest.MigrateTo(t, db, v060)
		var from sql.NullInt64
		var fromFix bool
		if err := db.DB.NewRaw(`SELECT "from_window_id", "from_fix" FROM "obligation_window" WHERE "id" = ?`,
			window).Scan(ctx, &from, &fromFix); err != nil {
			t.Fatal(err)
		}
		if from.Valid || fromFix {
			t.Errorf("upgraded, a v0.5.0 window counts from window %d or from a fix (%v)", from.Int64, fromFix)
		}
		var fixes int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "exploited_fix"`).Scan(ctx, &fixes); err != nil {
			t.Fatal(err)
		}
		if fixes != 0 {
			t.Errorf("upgraded, v0.5.0's record names %d fix releases", fixes)
		}
		// Configuration is the only source of a mapping, so v0.5.0's go.
		var mapped int
		if err := db.DB.NewRaw(`SELECT (SELECT COUNT(*) FROM "group_role") + (SELECT COUNT(*) FROM "group_role_all")`).
			Scan(ctx, &mapped); err != nil {
			t.Fatal(err)
		}
		if mapped != 0 {
			t.Errorf("upgraded, %d of v0.5.0's role mappings remain", mapped)
		}
		// Administration stays reachable, in both directions.
		var admins int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "group_admin"`).Scan(ctx, &admins); err != nil {
			t.Fatal(err)
		}
		if admins != 1 {
			t.Errorf("upgraded, %d of v0.5.0's administration mappings remain, want the one", admins)
		}
		var reference, malicious sql.NullString
		if err := db.DB.NewRaw(`SELECT "reference", "suspected_malicious" FROM "told_outside"`+
			` WHERE "id" = ?`, notice).Scan(ctx, &reference, &malicious); err != nil {
			t.Fatal(err)
		}
		if reference.Valid || malicious.Valid {
			t.Errorf("upgraded, a v0.5.0 notice says %v and %v", reference, malicious)
		}
		t.Run("TheDeclarationsAreTheTablesTheMigrationsBuild", func(t *testing.T) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV060(db.Server.Engine), nil)
		})

		// What the untagged release holds that v0.5.0 cannot.
		if _, err := db.DB.NewRaw(`INSERT INTO "obligation_window" ("name", "length_hours",`+
			` "declared_by", "declared_at", "live_name", "from_window_id", "from_fix")`+
			` SELECT ?, ?, "declared_by", "declared_at", ?, "id", ? FROM "obligation_window" WHERE "id" = ?`,
			"Final report", 24*30, "final report", false, window).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "told_place" ("told_id", "position", "place")`+
			` VALUES (?, ?, ?)`, notice, 0, "Ireland").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "obligation_window" ("name", "length_hours",`+
			` "declared_by", "declared_at", "live_name", "from_fix")`+
			` SELECT ?, ?, "declared_by", "declared_at", ?, ? FROM "obligation_window" WHERE "id" = ?`,
			"Fix available", 24*14, "fix available", true, window).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "stream" ("product_id", "name", "display_name",`+
			` "kind", "created_at") SELECT "product_id", ?, ?, ?, "recorded_at" FROM "exploited_here"`+
			` WHERE "id" = (SELECT "exploited_here_id" FROM "told_outside" WHERE "id" = ?)`,
			"v1.0.1", "v1.0.1", "tag", notice).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "exploited_fix" ("exploited_here_id", "stream_id",`+
			` "named_by", "named_at", "live_stream_id")`+
			` SELECT "tod"."exploited_here_id", "st"."id", "tod"."recorded_by", "tod"."recorded_at", "st"."id"`+
			` FROM "told_outside" AS "tod", "stream" AS "st" WHERE "tod"."id" = ? AND "st"."name" = ?`,
			notice, "v1.0.1").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// A role a group derived on every product, which v0.5.0 never clears.
		if _, err := db.DB.NewRaw(`INSERT INTO "role_grant_all" ("person_id", "role", "source", "active", "created_at")`+
			` SELECT "id", ?, ?, ?, "created_at" FROM "person" WHERE "identity" = ?`,
			"private-read", "derived", true, "obligation-admin").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		var derived int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "role_grant_all" WHERE "source" = ?`, "derived").
			Scan(ctx, &derived); err != nil {
			t.Fatal(err)
		}
		if derived != 0 {
			t.Errorf("rolled back, %d roles a group derived on every product remain", derived)
		}
		var windows, notices int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "obligation_window"`).Scan(ctx, &windows); err != nil {
			t.Fatal(err)
		}
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "told_outside"`).Scan(ctx, &notices); err != nil {
			t.Fatal(err)
		}
		if windows != 3 || notices != 1 {
			t.Errorf("rolled back, %d windows and %d notices remain, want 3 and 1", windows, notices)
		}
		// Qualified by the table. SQLite reads a bare quoted name that is no
		// column as a string, and answers.
		for _, gone := range []string{
			`SELECT "obligation_window"."from_window_id" FROM "obligation_window"`,
			`SELECT "told_outside"."reference" FROM "told_outside"`,
			`SELECT "told_outside"."suspected_malicious" FROM "told_outside"`,
			`SELECT "place" FROM "told_place"`,
			`SELECT "obligation_window"."from_fix" FROM "obligation_window"`,
			`SELECT "stream_id" FROM "exploited_fix"`,
			`SELECT "role" FROM "group_role_all"`,
			`SELECT "group_role"."product_name" FROM "group_role"`,
		} {
			if _, err := db.ExecContext(ctx, gone); err == nil {
				t.Errorf("rolled back, %s still answers", gone)
			}
		}

		// What v0.5.0 reads: a mapping names its product by row.
		if _, err := db.DB.NewRaw(`INSERT INTO "group_role" ("group_name", "product_id", "role", "created_at")`+
			` SELECT ?, "id", ?, "created_at" FROM "product"`, "kernel", "public-read").Exec(ctx); err != nil {
			t.Errorf("rolled back, v0.5.0 cannot map a group: %v", err)
		}

		dbtest.MigrateTo(t, db, v060)
		leaveAtLatest(t, ctx, db)
	})
}

// seedV050Obligation writes a window and a notice answering it as v0.5.0 held
// them, and returns both identifiers.
func seedV050Obligation(t *testing.T, ctx context.Context, db *database.DB) (window, notice int64) {
	t.Helper()
	at := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
	person, err := access.NewStore(db.DB).Ensure(ctx, "obligation-admin", "", access.Stated(true), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "vulnerability" ("identifier", "identifier_folded",`+
		` "exploited", "first_seen_at", "issue_id") VALUES (?, ?, ?, ?, ?)`,
		"CVE-2026-4040", "cve-2026-4040", false, at, 0).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var issue int64
	if err := db.DB.NewRaw(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`,
		"CVE-2026-4040").Scan(ctx, &issue); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.NewRaw(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, issue).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "product" ("name", "display_name", "created_at")`+
		` VALUES (?, ?, ?)`, "switch", "Switch", at).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var product, record int64
	if err := db.DB.NewRaw(`SELECT "id" FROM "product" WHERE "name" = ?`, "switch").
		Scan(ctx, &product); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "exploited_here" ("vulnerability_id", "product_id",`+
		` "known_at", "grounds", "recorded_by", "recorded_at", "live_vulnerability_id")`+
		` VALUES (?, ?, ?, ?, ?, ?, ?)`, issue, product, at, "A customer saw it.", person.ID, at, issue).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.NewRaw(`SELECT "id" FROM "exploited_here" WHERE "product_id" = ?`, product).
		Scan(ctx, &record); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "obligation_window" ("name", "length_hours",`+
		` "declared_by", "declared_at", "live_name") VALUES (?, ?, ?, ?, ?)`,
		"Notification", 72, person.ID, at, "notification").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.NewRaw(`SELECT "id" FROM "obligation_window" WHERE "live_name" = ?`,
		"notification").Scan(ctx, &window); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "told_outside" ("exploited_here_id", "window_id",`+
		` "recipient", "told_at", "said", "recorded_by", "recorded_at")`+
		` VALUES (?, ?, ?, ?, ?, ?, ?)`, record, window, "A regulator", at.Add(time.Hour),
		"An attack.", person.ID, at).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.NewRaw(`SELECT "id" FROM "told_outside" WHERE "exploited_here_id" = ?`, record).
		Scan(ctx, &notice); err != nil {
		t.Fatal(err)
	}
	return window, notice
}

// declarationsAreBuilt builds each declaration under a scratch name and
// compares its description with the table the migrations built, line for line
// in both directions. A built line madeElsewhere answers true for is one a
// later migration added, and is not held against the declaration.
//
// The scratch tables are dropped before it returns, and however the
// comparison ends, so what follows reads only what the migrations built.
func declarationsAreBuilt(t *testing.T, ctx context.Context, db *database.DB,
	declared map[string][]string, madeElsewhere func(table, line string) bool) {
	t.Helper()
	var made []string
	drop := func(ctx context.Context) {
		for _, table := range made {
			if _, err := db.ExecContext(ctx, `DROP TABLE "`+table+`"`); err != nil {
				t.Errorf("drop %s: %v", table, err)
			}
		}
		made = nil
	}
	t.Cleanup(func() { drop(context.WithoutCancel(ctx)) })
	defer drop(ctx)
	for table, statements := range declared {
		made = append(made, scratchPrefix+table)
		for _, stmt := range statements {
			if _, err := db.ExecContext(ctx, scratch(table, stmt)); err != nil {
				t.Fatalf("build %s's declaration under a scratch name: %v\n%s", table, err, stmt)
			}
		}
	}
	described := describe(t, ctx, db)
	compared := 0
	for table := range declared {
		built := linesOf(described, table, "")
		fromDeclaration := linesOf(described, scratchPrefix+table, scratchPrefix)
		if len(built) == 0 || len(fromDeclaration) == 0 {
			t.Errorf("%s described as %d lines built and %d declared, so nothing was compared",
				table, len(built), len(fromDeclaration))
			continue
		}
		compared++
		for _, line := range fromDeclaration {
			if !slices.Contains(built, line) {
				t.Errorf("%s is declared with %q and the migrations do not build it", table, line)
			}
		}
		for _, line := range built {
			if !slices.Contains(fromDeclaration, line) &&
				(madeElsewhere == nil || !madeElsewhere(table, line)) {
				t.Errorf("the migrations build %q on %s and it is not declared", line, table)
			}
		}
	}
	if compared == 0 || compared != len(declared) {
		t.Errorf("compared %d of the %d tables declared", compared, len(declared))
	}
}
