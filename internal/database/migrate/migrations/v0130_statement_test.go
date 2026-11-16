// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

// statementsV0120 is what seedStatementV0120 seeds: one VEX statement, and the
// older and the newer of two advisories about one subject.
type statementsV0120 struct {
	vex          int64
	older, newer int64
	product      int64
}

// seedStatementV0120 seeds statements a v0.12.0 deployment received.
func seedStatementV0120(t *testing.T, db *database.DB) statementsV0120 {
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
	said := func(source, document, status string, uploaded time.Time) int64 {
		t.Helper()
		exec(`INSERT INTO "received_vex_statement" ("product_id", "publisher", "source", "document_id",
			"vulnerability", "component", "about", "status", "document", "digest", "uploaded_by", "uploaded_at")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, product, "acme", source, document, "cve-2026-1102",
			"libbaz", "", status, document+".json", "digest", person, uploaded)
		return id(`SELECT MAX("id") FROM "received_vex_statement"`)
	}
	out := statementsV0120{vex: said("vex", "", "not_affected", at), product: product}
	// Two advisories from one publisher about one subject, which v0.12.0
	// left both standing.
	out.older = said("advisory", "ACME-1", "affected", at.Add(-time.Hour))
	out.newer = said("advisory", "ACME-2", "fixed", at)
	return out
}

// A v0.12.0 database's received statements gain when each was made, what
// overtook it and the remediation category, empty on every statement already
// held, and of two advisories from one publisher about one subject the older
// is set aside by the newer, whether the upgrade ran whole or a start of it
// stopped after the first column.
func statementPartV0130() partV0130 {
	return partV0130{
		name: "AStatementHeldBeforeTheUpgradeIsTimedAndTheOlderSetAside",
		seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
			seeded := seedStatementV0120(t, db)
			return func(t *testing.T) {
				ctx := t.Context()
				var held struct {
					SaidAt      *time.Time `bun:"said_at"`
					OvertakenBy *int64     `bun:"overtaken_by"`
				}
				if err := db.DB.NewRaw(`SELECT "said_at", "overtaken_by" FROM "received_vex_statement"
					WHERE "id" = ?`, seeded.vex).Scan(ctx, &held); err != nil {
					t.Fatal(err)
				}
				if held.SaidAt != nil || held.OvertakenBy != nil {
					t.Errorf("a statement held before the upgrade states %v and %v, want neither",
						held.SaidAt, held.OvertakenBy)
				}
				var older struct {
					Superseded  *time.Time `bun:"superseded_at"`
					OvertakenBy *int64     `bun:"overtaken_by"`
					Remediation *string    `bun:"remediation"`
				}
				if err := db.DB.NewRaw(`SELECT "superseded_at", "overtaken_by", "remediation" FROM "received_vex_statement"
					WHERE "id" = ?`, seeded.older).Scan(ctx, &older); err != nil {
					t.Fatal(err)
				}
				if older.Superseded == nil || older.OvertakenBy == nil || *older.OvertakenBy != seeded.newer {
					t.Errorf("the older of two advisories about one subject is set aside %v by %v, want by the newer %d",
						older.Superseded, older.OvertakenBy, seeded.newer)
				}
				if older.Remediation != nil {
					t.Errorf("an affected statement held before the upgrade states remediation %q, want none",
						*older.Remediation)
				}
				var standing int
				if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "received_vex_statement"
					WHERE "superseded_at" IS NULL AND "product_id" = ?`, seeded.product).Scan(ctx, &standing); err != nil {
					t.Fatal(err)
				}
				if standing != 2 {
					t.Errorf("%d statements stand after the upgrade, want the VEX one and the newer advisory", standing)
				}
			}
		},
		stops: []stopV0130{
			{"after the time", func(t *testing.T, db *database.DB) error {
				return migrations.StopV0130AfterStatementTime(t.Context(), db)
			}},
		},
	}
}
