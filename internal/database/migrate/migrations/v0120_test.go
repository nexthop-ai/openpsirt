// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// v0120 is the migration v0.12.0 carries v0.11.0's schema across with.
const v0120 = 46

// A v0.11.0 database is upgraded, and the tables v0.12.0 changes are as it
// declares them.
func TestAV0110DatabaseUpgradesToV0120(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0110)
		dbtest.MigrateTo(t, db, v0120)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0120(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// A start that stopped after adding the issue dates and the checked scan's
// column carries on, and makes the index. On MySQL and MariaDB each column
// commits by itself.
func TestTheV0120UpgradeStepsOverColumnsAlreadyThere(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0110)
		for _, stmt := range []string{
			`ALTER TABLE "vulnerability" ADD COLUMN "published_at" ` + timestampOn(db.Server.Engine) + ` NULL`,
			`ALTER TABLE "vulnerability" ADD COLUMN "modified_at" ` + timestampOn(db.Server.Engine) + ` NULL`,
			`ALTER TABLE "vulnerability" ADD COLUMN "dates_asked_at" ` + timestampOn(db.Server.Engine) + ` NULL`,
		} {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("make what a stopped upgrade left: %v", err)
			}
		}
		dbtest.MigrateTo(t, db, v0120)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0120(db.Server.Engine))
		leaveAtLatest(t, ctx, db)
	})
}

// timestampOn is how an engine declares a moment, as the migrations do.
func timestampOn(engine database.Engine) string {
	switch engine {
	case database.Postgres:
		return "TIMESTAMPTZ"
	case database.SQLite:
		return "DATETIME"
	default:
		return "DATETIME(6)"
	}
}

// An inventory v0.11.0 left replaced owes no check after the upgrade; the one
// still current owes one once something replaces it.
func TestABranchInventoryReplacedBeforeTheUpgradeOwesNoCheck(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0110)
		at := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
		}
		id := func(query string) int64 {
			t.Helper()
			var out int64
			if err := db.DB.NewRaw(query).Scan(ctx, &out); err != nil {
				t.Fatalf("%v\n%s", err, query)
			}
			return out
		}
		exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
		product := id(`SELECT MAX("id") FROM "product"`)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "main", "main", "branch", at)
		line := id(`SELECT MAX("id") FROM "branch_or_tag"`)
		exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "image", "Image", true, at)
		variant := id(`SELECT MAX("id") FROM "variant"`)
		exec(`INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`, line, variant, at)
		build := id(`SELECT MAX("id") FROM "build"`)
		scanned := func(n int) int64 {
			exec(`INSERT INTO "scan" ("build_id", "content_hash", "built_at", "received_at", "parser_version",
				"status", "components") VALUES (?, ?, ?, ?, ?, ?, ?)`,
				build, fmt.Sprintf("hash-%d", n), at.Add(time.Duration(n)*time.Hour),
				at.Add(time.Duration(n)*time.Hour), "test", "accepted", 1)
			return id(`SELECT MAX("id") FROM "scan"`)
		}
		replaced, current := scanned(1), scanned(2)

		dbtest.MigrateTo(t, db, v0120)
		after := scanned(3)
		unchecked := func(scan int64) bool {
			var out bool
			if err := db.DB.NewRaw(`SELECT "replaced_unchecked" FROM "scan" WHERE "id" = ?`, scan).
				Scan(ctx, &out); err != nil {
				t.Fatal(err)
			}
			return out
		}
		switch {
		case !unchecked(replaced):
			t.Error("an inventory replaced before the upgrade owes a check")
		case unchecked(current):
			t.Error("an inventory replaced after the upgrade owes none")
		case unchecked(after):
			t.Error("an inventory arriving after the upgrade owes none")
		}
		leaveAtLatest(t, ctx, db)
	})
}
