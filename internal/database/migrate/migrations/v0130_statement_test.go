// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// seedStatementV0120 seeds one statement a v0.12.0 deployment received, and
// answers it.
func seedStatementV0120(t *testing.T, db *database.DB) int64 {
	t.Helper()
	ctx := t.Context()
	at := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
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
	exec(`INSERT INTO "party" ("kind") VALUES (?)`, "person")
	party := id(`SELECT MAX("id") FROM "party"`)
	exec(`INSERT INTO "person" ("party_id", "identity", "is_admin", "is_bootstrap", "admin_derived", "audits",
		"audits_derived", "email_source", "digest", "digest_unassigned", "created_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		party, "uploader", false, false, false, false, false, "", false, false, at)
	person := id(`SELECT MAX("id") FROM "person"`)
	exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "said", "Said", at)
	product := id(`SELECT MAX("id") FROM "product"`)
	exec(`INSERT INTO "received_vex_statement" ("product_id", "publisher", "source", "document_id",
		"vulnerability", "component", "about", "status", "document", "digest", "uploaded_by", "uploaded_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, product, "acme", "vex", "", "cve-2026-1102", "libbaz", "",
		"not_affected", "acme.json", "digest", person, at)
	return id(`SELECT MAX("id") FROM "received_vex_statement"`)
}

// A v0.12.0 database's received statements gain when each was made and what
// overtook it, empty on every statement already held, whether the upgrade ran
// whole or a start of it stopped after the first column; the stop is one
// SQLite never makes, since it changes a table in one transaction.
func TestAV0120DatabaseResumesTheV0130StatementUpgradeFromEveryStop(t *testing.T) {
	for _, stop := range []struct {
		name string
		make func(t *testing.T, db *database.DB) error
	}{
		{"whole", nil},
		{"after the time", func(t *testing.T, db *database.DB) error {
			return migrations.StopV0130AfterStatementTime(t.Context(), db)
		}},
	} {
		t.Run(stop.name, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				ctx := t.Context()
				if stop.make != nil && db.Server.Engine == database.SQLite {
					t.Skip("SQLite changes a table in one transaction, so it never stops there")
				}
				dbtest.Empty(t, db)
				dbtest.MigrateTo(t, db, v0120)
				statement := seedStatementV0120(t, db)
				if stop.make != nil {
					if err := stop.make(t, db); err != nil {
						t.Fatalf("make what a stopped upgrade left: %v", err)
					}
				}
				dbtest.MigrateTo(t, db, v0130)
				declarationsAreBuilt(t, ctx, db, migrations.StatementsV0130(db.Server.Engine))
				var held struct {
					SaidAt      *time.Time `bun:"said_at"`
					OvertakenBy *int64     `bun:"overtaken_by"`
				}
				if err := db.DB.NewRaw(`SELECT "said_at", "overtaken_by" FROM "received_vex_statement"
					WHERE "id" = ?`, statement).Scan(ctx, &held); err != nil {
					t.Fatal(err)
				}
				if held.SaidAt != nil || held.OvertakenBy != nil {
					t.Errorf("a statement held before the upgrade states %v and %v, want neither",
						held.SaidAt, held.OvertakenBy)
				}
				leaveAtLatest(t, ctx, db)
			})
		})
	}
}
