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
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
)

// rulesV0100 is, in a v0.10.0 database, a standing rule handing work to a
// team.
type rulesV0100 struct{ rule int64 }

func seedRulesV0100(t *testing.T, ctx context.Context, db *database.DB) rulesV0100 {
	t.Helper()
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
	person, product := declared.Person.ID, declared.Product.ID
	exec(`INSERT INTO "party" ("kind") VALUES (?)`, "team")
	party := id(`SELECT MAX("id") FROM "party"`)
	exec(`INSERT INTO "team" ("party_id", "name", "created_at") VALUES (?, ?, ?)`, party, "curlers", at)
	team := id(`SELECT "id" FROM "team" WHERE "name" = ?`, "curlers")

	var out rulesV0100
	exec(`INSERT INTO "routing_rule" ("product_id", "team_id", "name", "ordinal", "upstream", "created_by",
		"created_at") VALUES (?, ?, ?, ?, ?, ?, ?)`, product, team, "curl to the curlers", 1, "curl", person, at)
	out.rule = id(`SELECT MAX("id") FROM "routing_rule"`)
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

// A v0.10.0 database holding a standing rule is upgraded, and every row reads
// back under v0.11.0's names in the shape the release declares.
func TestAV0100DatabaseTakesTheV0110RuleNames(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		seeded := seedRulesV0100(t, ctx, db)
		dbtest.MigrateTo(t, db, v0110)
		declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
		seeded.renamedAs(t, ctx, db)
		leaveAtLatest(t, ctx, db)
	})
}

// An upgrade stopped after any one of these renames is started again, and
// leaves what one that did not stop leaves.
func TestAnUpgradeStoppedPartWayThroughTheRuleRenamesResumes(t *testing.T) {
	for _, stop := range []struct {
		after string
		// servers is a constraint SQLite does not rename.
		servers bool
	}{
		{after: "routing_rule"},
		{after: "routed_by"},
		{after: "routing_rule_team_fk", servers: true},
		{after: "routing_rule_order_idx"},
	} {
		t.Run(stop.after, func(t *testing.T) {
			dbtest.Each(t, func(t *testing.T, db *database.DB) {
				if stop.servers && db.Server.Engine == database.SQLite {
					t.Skip("SQLite keeps the constraint names v0.10.0 wrote")
				}
				ctx := t.Context()
				dbtest.Empty(t, db)
				dbtest.MigrateTo(t, db, v0100)
				seeded := seedRulesV0100(t, ctx, db)
				stopped, err := migrations.StopV0110RenamingAfter(ctx, db, stop.after)
				if err != nil {
					t.Fatal(err)
				}
				if !stopped {
					t.Fatalf("nothing renames %s here, so this stopped nothing", stop.after)
				}
				dbtest.MigrateTo(t, db, v0110)
				declarationsAreBuilt(t, ctx, db, migrations.StatementsV0110(db.Server.Engine))
				seeded.renamedAs(t, ctx, db)
				leaveAtLatest(t, ctx, db)
			})
		})
	}
}
