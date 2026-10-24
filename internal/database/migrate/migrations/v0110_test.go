// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// v0110 is the migration v0.11.0 carries v0.10.0's schema across with.
const v0110 = 45

// A v0.10.0 database is upgraded, and every issue it held says what sort of
// issue it is: a flaw where somebody recorded a finding of it here, and a
// published vulnerability otherwise.
func TestAV0100DatabaseUpgradesToV0110(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		declared, err := world.Declare(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		at := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
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
		issue := func(name string) int64 {
			t.Helper()
			exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
				VALUES (?, ?, ?, ?, ?)`, name, name, false, at, 0)
			return id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, name)
		}
		scanned, recorded, untouched := issue("cve-2026-1100"), issue("sonic-2026-123456"), issue("cve-2026-1101")
		exec(`UPDATE "vulnerability" SET "issue_id" = "id"`)
		exec(`INSERT INTO "component" ("identity", "name", "version", "name_folded", "fold_key", "first_seen_at")
			VALUES (?, ?, ?, ?, ?, ?)`, "libfoo", "libfoo", "1.0", "libfoo", "libfoo", at)
		component := id(`SELECT "id" FROM "component" WHERE "identity" = ?`, "libfoo")
		finding := func(issue int64, kind, visibility string) {
			t.Helper()
			exec(`INSERT INTO "finding" ("target_id", "kind", "visibility", "vulnerability_id", "component_id",
				"place_identity", "urgency", "urgency_exploited", "urgency_exploited_here",
				"urgency_shipped", "opened_at")
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				declared.Target.ID, kind, visibility, issue, component, "place-libfoo", 1, false, false, true, at)
		}
		finding(scanned, "vulnerability", "public")
		finding(recorded, "entered", "private")

		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		for issue, want := range map[int64]string{scanned: "vulnerability", recorded: "flaw", untouched: "vulnerability"} {
			var got string
			if err := db.DB.NewRaw(`SELECT "kind" FROM "vulnerability" WHERE "id" = ?`, issue).Scan(ctx, &got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("issue %d is a %q after the upgrade, want %q", issue, got, want)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

// A start that stopped after adding the column is carried on: on MySQL and
// MariaDB the column commits by itself.
func TestTheV0110UpgradeStepsOverAnIssueKindAlreadyThere(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		if _, err := db.ExecContext(ctx,
			`ALTER TABLE "vulnerability" ADD COLUMN "kind" `+kindOf(db)+` DEFAULT 'vulnerability' NOT NULL`); err != nil {
			t.Fatalf("make what a stopped upgrade left: %v", err)
		}
		dbtest.MigrateTo(t, db, v0110)
		leaveAtLatest(t, ctx, db)
	})
}

// kindOf is how an engine declares a short word.
func kindOf(db *database.DB) string {
	if db.Server.Engine == database.SQLite {
		return "TEXT"
	}
	return "VARCHAR(16)"
}
