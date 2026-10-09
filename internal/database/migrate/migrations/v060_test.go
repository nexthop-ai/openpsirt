// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v060 is the migration v0.6.0 carries v0.5.0's schema across with.
const v060 = 40

// A v0.5.0 database holding a window, a notice and group mappings is upgraded.
// The window counts from the moment the attack became known rather than from
// a notice or a fix, the notice says none of what a notice may now carry, the
// record names no fix release, the role mappings are gone and the
// administration mapping remains.
func TestAV050DatabaseUpgradesToV060(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
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
		// Administration stays reachable.
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
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV060(db.Server.Engine))
		})

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
// in both directions.
//
// The scratch tables are dropped before it returns, and however the
// comparison ends, so what follows reads only what the migrations built.
func declarationsAreBuilt(t *testing.T, ctx context.Context, db *database.DB,
	declared map[string][]string) {
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
			if !slices.Contains(fromDeclaration, line) {
				t.Errorf("the migrations build %q on %s and it is not declared", line, table)
			}
		}
	}
	if compared == 0 || compared != len(declared) {
		t.Errorf("compared %d of the %d tables declared", compared, len(declared))
	}
}

// Upgraded, a credential in force holds its name in force and a withdrawn one
// holds none, so the withdrawn name may be given again.
func TestAV050CredentialsNameInForceSurvivesTheUpgrade(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v050)
		tables := []string{"api_key", "personal_token"}
		at := time.Date(2026, 9, 20, 14, 0, 0, 0, time.UTC)
		person, err := access.NewStore(db.DB).Ensure(ctx, "token-holder", "", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "product" ("name", "display_name", "created_at")`+
			` VALUES (?, ?, ?)`, "keyed", "Keyed", at).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		var product int64
		if err := db.DB.NewRaw(`SELECT "id" FROM "product" WHERE "name" = ?`, "keyed").Scan(ctx, &product); err != nil {
			t.Fatal(err)
		}
		// insert writes one credential, with its name in force where the
		// schema has one.
		insert := func(table, name, secret string, revoked bool, live bool) error {
			t.Helper()
			var when any
			if revoked {
				when = at
			}
			columns := `"name", "secret_hash", "created_at", "revoked_at"`
			values := []any{name, secret, at, when}
			if table == "api_key" {
				columns += `, "product_id"`
				values = append(values, product)
			} else {
				columns += `, "person_id", "expires_at"`
				values = append(values, person.ID, at.Add(time.Hour))
			}
			if live {
				columns += `, "live_name"`
				values = append(values, name)
			}
			marks := strings.TrimSuffix(strings.Repeat("?, ", len(values)), ", ")
			_, err := db.DB.NewRaw(`INSERT INTO "`+table+`" (`+columns+`) VALUES (`+marks+`)`,
				values...).Exec(ctx)
			return err
		}
		for _, table := range tables {
			for _, c := range []struct {
				name    string
				revoked bool
			}{{"live", false}, {"gone", true}} {
				if err := insert(table, c.name, table+"-"+c.name, c.revoked, false); err != nil {
					t.Fatalf("%s %q: %v", table, c.name, err)
				}
			}
		}

		dbtest.MigrateTo(t, db, v060)
		for _, table := range tables {
			for name, want := range map[string]sql.NullString{
				"live": {String: "live", Valid: true}, "gone": {},
			} {
				var got sql.NullString
				if err := db.DB.NewRaw(`SELECT "live_name" FROM "`+table+`" WHERE "name" = ?`, name).
					Scan(ctx, &got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Errorf("upgraded, %s %q holds %v in force, want %v", table, name, got, want)
				}
			}
			if err := insert(table, "gone", table+"-again", false, true); err != nil {
				t.Errorf("upgraded, %s refuses a withdrawn name given again: %v", table, err)
			}
			if err := insert(table, "live", table+"-twice", false, true); err == nil {
				t.Errorf("upgraded, %s gave a name in force to a second credential", table)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}
