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

// v0130Override is the migration v0.13.0 carries v0.12.0's schema across
// with.
const v0130Override = 47

// marksV0120 is a v0.12.0 advisory marking one release affected still, and
// one it was cleared on.
type marksV0120 struct {
	advisory, product, issue, person, line, kept, cleared int64
}

// seedMarksV0120 seeds a v0.12.0 advisory with a release marked affected and
// one cleared.
func seedMarksV0120(t *testing.T, db *database.DB) marksV0120 {
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
	var out marksV0120
	exec(`INSERT INTO "party" ("kind") VALUES (?)`, "person")
	party := id(`SELECT MAX("id") FROM "party"`)
	exec(`INSERT INTO "person" ("party_id", "identity", "is_admin", "is_bootstrap", "admin_derived", "audits",
		"audits_derived", "email_source", "digest", "digest_unassigned", "created_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		party, "writer", false, false, false, false, false, "", false, false, at)
	out.person = id(`SELECT MAX("id") FROM "person"`)
	exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
	out.product = id(`SELECT MAX("id") FROM "product"`)
	exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
		VALUES (?, ?, ?, ?, ?)`, out.product, "main", "main", "branch", at)
	out.line = id(`SELECT MAX("id") FROM "branch_or_tag"`)
	variant := func(name string) int64 {
		exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
			VALUES (?, ?, ?, ?, ?)`, out.product, name, name, true, at)
		return id(`SELECT MAX("id") FROM "variant"`)
	}
	out.kept, out.cleared = variant("image"), variant("lab")
	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "kind", "exploited",
		"first_seen_at", "issue_id") VALUES (?, ?, ?, ?, ?, ?)`, "cve-2026-1", "cve-2026-1", "vulnerability",
		false, at, 0)
	out.issue = id(`SELECT MAX("id") FROM "vulnerability"`)
	exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, out.issue)
	exec(`INSERT INTO "advisory" ("identifier", "identifier_folded", "minted_year", "mint_number",
		"minted_at", "minted_by") VALUES (?, ?, ?, ?, ?, ?)`, "EX-2026-0001", "ex-2026-0001", 2026, 1, at,
		out.person)
	out.advisory = id(`SELECT MAX("id") FROM "advisory"`)
	exec(`INSERT INTO "advisory_override" ("advisory_id", "product_id", "vulnerability_id", "branch_or_tag_id",
		"variant_id", "set_at", "set_by") VALUES (?, ?, ?, ?, ?, ?, ?)`,
		out.advisory, out.product, out.issue, out.line, out.kept, at, out.person)
	exec(`INSERT INTO "advisory_override" ("advisory_id", "product_id", "vulnerability_id", "branch_or_tag_id",
		"variant_id", "set_at", "set_by", "removed_at", "removed_by") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		out.advisory, out.product, out.issue, out.line, out.cleared, at, out.person, at.Add(time.Hour), out.person)
	return out
}

// checkLive checks each mark after the upgrade, and that a release is marked
// once among the rows marking it alone.
func (m marksV0120) checkLive(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	live := func(variant int64) *bool {
		t.Helper()
		var out *bool
		if err := db.DB.NewRaw(`SELECT "live" FROM "advisory_override" WHERE "variant_id" = ?`, variant).
			Scan(ctx, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := live(m.kept); got == nil || !*got {
		t.Errorf("a release marked affected is marked %v, want true", got)
	}
	if got := live(m.cleared); got != nil {
		t.Errorf("a release cleared is marked %v, want null", *got)
	}
	at := time.Date(2026, 11, 13, 2, 0, 0, 0, time.UTC)
	mark := func(variant int64) error {
		_, err := db.DB.NewRaw(`INSERT INTO "advisory_override" ("advisory_id", "product_id",
			"vulnerability_id", "branch_or_tag_id", "variant_id", "set_at", "set_by", "live")
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			m.advisory, m.product, m.issue, m.line, variant, at, m.person, true).Exec(ctx)
		return err
	}
	if err := mark(m.cleared); err != nil {
		t.Errorf("a release cleared could not be marked again: %v", err)
	}
	if err := mark(m.kept); err == nil {
		t.Error("a release marked affected was marked a second time")
	}
}

// A v0.12.0 database's release marks are marked by whether each still stands,
// whether the upgrade ran whole or a start of it stopped after the column or
// after the rule holding it; the second and third are stops SQLite never
// makes, since it changes a table in one transaction.
func TestAV0120DatabaseResumesTheV0130MarkUpgradeFromEveryStop(t *testing.T) {
	for _, stop := range []struct {
		name string
		make func(t *testing.T, db *database.DB) error
	}{
		{"whole", nil},
		{"after the column", func(t *testing.T, db *database.DB) error {
			return migrations.StopV0130AfterOverrideLiveColumn(t.Context(), db)
		}},
		{"after the rule", func(t *testing.T, db *database.DB) error {
			return migrations.StopV0130AfterOverrideLiveRule(t.Context(), db)
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
				marks := seedMarksV0120(t, db)
				if stop.make != nil {
					if err := stop.make(t, db); err != nil {
						t.Fatalf("make what a stopped upgrade left: %v", err)
					}
				}
				dbtest.MigrateTo(t, db, v0130Override)
				declarationsAreBuilt(t, ctx, db, migrations.StatementsV0130(db.Server.Engine))
				marks.checkLive(t, db)
				leaveAtLatest(t, ctx, db)
			})
		})
	}
}
