// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// rulesV0100 is, in a v0.10.0 database, a standing rule handing work to a
// team, a supplier whose advisories are read, a word put on a finding, a
// supplier's VEX statement and a VEX document that went out.
type rulesV0100 struct{ rule, feed, label, received, published int64 }

func seedRulesV0100(t *testing.T, ctx context.Context, db *database.DB) rulesV0100 {
	t.Helper()
	declared := worldBeforeV0110(t, ctx, db)
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
	person, product := declared.Person.ID, declared.Product.ID
	exec(`INSERT INTO "party" ("kind") VALUES (?)`, "team")
	party := id(`SELECT MAX("id") FROM "party"`)
	exec(`INSERT INTO "team" ("party_id", "name", "created_at") VALUES (?, ?, ?)`, party, "curlers", at)
	team := id(`SELECT "id" FROM "team" WHERE "name" = ?`, "curlers")

	var out rulesV0100
	exec(`INSERT INTO "routing_rule" ("product_id", "team_id", "name", "ordinal", "upstream", "created_by",
		"created_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, product, team, "curl to the curlers", 1, "curl", person, at)
	out.rule = id(`SELECT MAX("id") FROM "routing_rule"`)
	exec(`INSERT INTO "advisory_source" ("product_id", "name", "display_name", "url", "created_by", "created_at")
		VALUES (?, ?, ?, ?, ?, ?)`, product, "examplelinux", "ExampleLinux",
		"https://example.com/.well-known/csaf/provider-metadata.json", person, at)
	out.feed = id(`SELECT MAX("id") FROM "advisory_source"`)
	exec(`INSERT INTO "vulnerability" ("identifier", "identifier_folded", "exploited", "first_seen_at", "issue_id")
		VALUES (?, ?, ?, ?, ?)`, "CVE-2026-1102", "cve-2026-1102", false, at, 0)
	issue := id(`SELECT "id" FROM "vulnerability" WHERE "identifier" = ?`, "CVE-2026-1102")
	exec(`UPDATE "vulnerability" SET "issue_id" = "id" WHERE "id" = ?`, issue)
	exec(`INSERT INTO "component" ("identity", "name", "version", "name_folded", "fold_key", "first_seen_at")
		VALUES (?, ?, ?, ?, ?, ?)`, "libbaz", "libbaz", "1.0", "libbaz", "libbaz", at)
	component := id(`SELECT "id" FROM "component" WHERE "identity" = ?`, "libbaz")
	exec(`INSERT INTO "finding_tag" ("product_id", "vulnerability_id", "component_id", "tag", "typed",
		"added_by", "added_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, product, issue, component, "waiting", "Waiting", person, at)
	out.label = id(`SELECT MAX("id") FROM "finding_tag"`)
	exec(`INSERT INTO "vex_statement" ("product_id", "publisher", "source", "document_id", "vulnerability",
		"component", "about", "status", "document", "digest", "uploaded_by", "uploaded_at")
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, product, "acme", "vex", "", "cve-2026-1102", "libbaz", "",
		"not_affected", "acme.json", "digest", person, at)
	out.received = id(`SELECT MAX("id") FROM "vex_statement"`)
	exec(`INSERT INTO "vex_issuance" ("target_id", "kind", "ordinal", "digest", "document", "issued_by",
		"issued_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, declared.Build.ID, "ours", 1, "digest", "{}", person, at)
	out.published = id(`SELECT MAX("id") FROM "vex_issuance"`)
	return out
}

// renamedAs asserts every row the seed wrote is read back under v0.11.0's
// names.
func (w rulesV0100) renamedAs(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	for _, c := range []struct {
		what, query string
		id          int64
	}{
		{"the assignment rule", `SELECT COUNT(*) FROM "assignment_rule"
			WHERE "id" = ? AND "name" = 'curl to the curlers' AND NOT "reports"`, w.rule},
		{"the supplier advisory feed", `SELECT COUNT(*) FROM "supplier_advisory_feed"
			WHERE "id" = ? AND "display_name" = 'ExampleLinux'`, w.feed},
		{"the label", `SELECT COUNT(*) FROM "finding_label"
			WHERE "id" = ? AND "label" = 'waiting' AND "typed" = 'Waiting'`, w.label},
		{"the received VEX statement", `SELECT COUNT(*) FROM "received_vex_statement"
			WHERE "id" = ? AND "publisher" = 'acme'`, w.received},
		{"the published VEX", `SELECT COUNT(*) FROM "published_vex"
			WHERE "id" = ? AND "ordinal" = 1`, w.published},
	} {
		var n int
		if err := db.DB.NewRaw(c.query, c.id).Scan(ctx, &n); err != nil {
			t.Fatalf("read %s: %v", c.what, err)
		}
		if n != 1 {
			t.Errorf("%s reads %d rows after the upgrade, want 1", c.what, n)
		}
	}
}

// An upgrade stopped after each of these renames in turn, every start resuming
// the one before it, is started again, and leaves what one that did not stop
// leaves. One database per engine runs every stop, in the order the upgrade
// renames, as TestAnUpgradeStoppedPartWayThroughItsRenamesResumes says.
func TestAnUpgradeStoppedPartWayThroughTheRuleRenamesResumes(t *testing.T) {
	stops := inRenameOrder(t, []renameStop{
		{after: "routing_rule"},
		{after: "routed_by"},
		{after: "routing_rule_team_fk", servers: true},
		{after: "routing_rule_order_idx"},
		{after: "advisory_source"},
		{after: "advisory_source_named_once", servers: true},
		{after: "advisory_source_due_idx"},
		{after: "finding_tag"},
		{after: "tag"},
		{after: "finding_tag_once", servers: true},
		{after: "finding_tag_named_idx"},
		{after: "vex_statement"},
		{after: "vex_statement_by_fk", servers: true},
		{after: "vex_statement_from_idx"},
		{after: "vex_issuance"},
		{after: "vex_issuance_once_per_kind", servers: true},
		{after: "vex_issuance_by_fk", servers: true},
	})
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		seeded := seedRulesV0100(t, ctx, db)
		for _, stop := range stops {
			if stop.servers && db.Server.Engine == database.SQLite {
				continue // SQLite keeps the constraint names v0.10.0 wrote.
			}
			stopAt(t, stop.after, func() (bool, error) {
				return migrations.StopV0110RenamingAfter(ctx, db, stop.after)
			})
		}
		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		seeded.renamedAs(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}
