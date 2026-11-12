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

// v0130 is the migration v0.13.0 carries v0.12.0's schema across with.
const v0130 = 47

// coversV0120 is a v0.12.0 advisory covering one issue still, and one it was
// taken off.
type coversV0120 struct {
	advisory, product, person, kept, dropped int64
}

// seedCoversV0120 seeds a v0.12.0 advisory with an issue on it and one taken
// off it.
func seedCoversV0120(t *testing.T, db *database.DB) coversV0120 {
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
	var out coversV0120
	exec(`INSERT INTO "party" ("kind") VALUES (?)`, "person")
	party := id(`SELECT MAX("id") FROM "party"`)
	exec(`INSERT INTO "person" ("party_id", "identity", "is_admin", "is_bootstrap", "admin_derived", "audits",
		"audits_derived", "email_source", "digest", "digest_unassigned", "created_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		party, "writer", false, false, false, false, false, "", false, false, at)
	out.person = id(`SELECT MAX("id") FROM "person"`)
	exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
	out.product = id(`SELECT MAX("id") FROM "product"`)
	issue := func(name string) int64 {
		exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "kind", "exploited",
			"first_seen_at", "issue_id") VALUES (?, ?, ?, ?, ?, ?)`, name, name, "vulnerability", false, at, 0)
		made := id(`SELECT MAX("id") FROM "vulnerability"`)
		exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, made)
		return made
	}
	out.kept, out.dropped = issue("cve-2026-1"), issue("cve-2026-2")
	exec(`INSERT INTO "advisory" ("identifier", "identifier_folded", "minted_year", "mint_number",
		"minted_at", "minted_by") VALUES (?, ?, ?, ?, ?, ?)`, "EX-2026-0001", "ex-2026-0001", 2026, 1, at,
		out.person)
	out.advisory = id(`SELECT MAX("id") FROM "advisory"`)
	exec(`INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id", "added_at", "added_by")
		VALUES (?, ?, ?, ?, ?)`, out.advisory, out.product, out.kept, at, out.person)
	exec(`INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id", "added_at", "added_by",
		"removed_at", "removed_by") VALUES (?, ?, ?, ?, ?, ?, ?)`,
		out.advisory, out.product, out.dropped, at, out.person, at.Add(time.Hour), out.person)
	return out
}

// checkLive checks each cover's mark after the upgrade, and that an issue is
// unique among the rows on the advisory alone.
func (c coversV0120) checkLive(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	live := func(issue int64) *bool {
		t.Helper()
		var out *bool
		if err := db.DB.NewRaw(`SELECT "live" FROM "advisory_issue" WHERE "vulnerability_id" = ?`, issue).
			Scan(ctx, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if got := live(c.kept); got == nil || !*got {
		t.Errorf("an issue on the advisory is marked %v, want true", got)
	}
	if got := live(c.dropped); got != nil {
		t.Errorf("an issue taken off the advisory is marked %v, want null", *got)
	}
	at := time.Date(2026, 11, 13, 2, 0, 0, 0, time.UTC)
	if _, err := db.DB.NewRaw(`INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id",
		"added_at", "added_by", "live") VALUES (?, ?, ?, ?, ?, ?)`,
		c.advisory, c.product, c.dropped, at, c.person, true).Exec(ctx); err != nil {
		t.Errorf("an issue taken off could not be put back on: %v", err)
	}
	if _, err := db.DB.NewRaw(`INSERT INTO "advisory_issue" ("advisory_id", "product_id", "vulnerability_id",
		"added_at", "added_by", "live") VALUES (?, ?, ?, ?, ?, ?)`,
		c.advisory, c.product, c.kept, at, c.person, true).Exec(ctx); err == nil {
		t.Error("an issue on the advisory was put on it a second time")
	}
}

// A v0.12.0 database's advisory covers are marked by whether each is still on
// the advisory, whether the upgrade ran whole or a start of it stopped after
// the column or after the rule holding it; the second and third are stops
// SQLite never makes, since it changes a table in one transaction.
func TestAV0120DatabaseResumesTheV0130UpgradeFromEveryStop(t *testing.T) {
	for _, stop := range []struct {
		name string
		make func(t *testing.T, db *database.DB) error
	}{
		{"whole", nil},
		{"after the column", func(t *testing.T, db *database.DB) error {
			return migrations.StopV0130AfterLiveColumn(t.Context(), db)
		}},
		{"after the rule", func(t *testing.T, db *database.DB) error {
			return migrations.StopV0130AfterLiveRule(t.Context(), db)
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
				covers := seedCoversV0120(t, db)
				if stop.make != nil {
					if err := stop.make(t, db); err != nil {
						t.Fatalf("make what a stopped upgrade left: %v", err)
					}
				}
				dbtest.MigrateTo(t, db, v0130)
				declarationsAreBuilt(t, ctx, db, migrations.StatementsV0130(db.Server.Engine))
				covers.checkLive(t, db)
				leaveAtLatest(t, ctx, db)
			})
		})
	}
}

// A v0.12.0 database's package identifiers lose the credential a qualifier's
// address held, on the component, the node and the image version, and keep
// every qualifier holding none.
func TestTheV0130UpgradeTakesCredentialsOutOfPackageIdentifiers(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
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
		const (
			leaky = "pkg:golang/example.com/x@v1?vcs_url=git%2Bhttps://oauth2:glpat-SECRET@gitlab.example.com/x.git&arch=amd64" //nolint:gosec // G101: the credential this upgrade takes out
			clean = "pkg:golang/example.com/x@v1?vcs_url=git%2Bhttps://gitlab.example.com/x.git&arch=amd64"
			kept  = "pkg:npm/%40scope/y@2?vcs_url=git%2Bhttps://github.com/scope/y.git"
		)
		exec(`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`, "p", "P", at)
		product := id(`SELECT MAX("id") FROM "product"`)
		exec(`INSERT INTO "branch_or_tag" ("product_id", "name", "display_name", "kind", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "main", "main", "branch", at)
		line := id(`SELECT MAX("id") FROM "branch_or_tag"`)
		exec(`INSERT INTO "variant" ("product_id", "name", "display_name", "customer_facing", "created_at")
			VALUES (?, ?, ?, ?, ?)`, product, "image", "Image", true, at)
		variant := id(`SELECT MAX("id") FROM "variant"`)
		exec(`INSERT INTO "build" ("branch_or_tag_id", "variant_id", "created_at") VALUES (?, ?, ?)`,
			line, variant, at)
		build := id(`SELECT MAX("id") FROM "build"`)
		exec(`INSERT INTO "scan" ("build_id", "content_hash", "built_at", "received_at", "parser_version",
			"status", "components") VALUES (?, ?, ?, ?, ?, ?, ?)`, build, "hash", at, at, "test", "accepted", 2)
		scan := id(`SELECT MAX("id") FROM "scan"`)
		for _, purl := range []string{leaky, kept} {
			exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "name_folded", "fold_key",
				"first_seen_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, purl[:20], purl, "x", "1", "x", purl[:20], at)
			component := id(`SELECT MAX("id") FROM "component"`)
			exec(`INSERT INTO "graph_node" ("build_id", "component_id", "is_root", "opened_scan_id", "purl")
				VALUES (?, ?, ?, ?, ?)`, build, component, false, scan, purl)
			node := id(`SELECT MAX("id") FROM "graph_node"`)
			exec(`INSERT INTO "image_version" ("node_id", "version", "purl", "opened_scan_id")
				VALUES (?, ?, ?, ?)`, node, "1", purl, scan)
		}

		dbtest.MigrateTo(t, db, v0130)

		for _, table := range []string{"component", "graph_node", "image_version"} {
			var got []string
			if err := db.DB.NewRaw(`SELECT "purl" FROM "`+table+`" ORDER BY "id"`).Scan(ctx, &got); err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || got[0] != clean || got[1] != kept {
				t.Errorf("%s holds %q after the upgrade, want %q and %q", table, got, clean, kept)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}
