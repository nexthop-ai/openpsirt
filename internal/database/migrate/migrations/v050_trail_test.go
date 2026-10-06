// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/uptrace/bun"
)

// trailRows is what the trail check's two rows are about: the change a person
// made under v0.4.0, and the one configuration makes once upgraded. Other
// checks write to the trail too, so these are the rows it reads.
var trailRows = []string{"triage-floor", "operator"}

// Upgraded, every trail row v0.4.0 wrote is a person's and keeps its person,
// and configuration may then record a change with no person behind it.
func everyTrailRowIsAPersons() upgradeCheck {
	var (
		built []string
		admin int64
	)
	return upgradeCheck{
		name: "AnUpgradeKeepsEveryTrailRowAPersons",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			built = linesOf(describe(t, ctx, db), "admin_change", "")
			if len(built) == 0 {
				t.Fatal("the v0.4.0 trail described as nothing, so nothing is compared")
			}
			person, err := access.NewStore(db.DB).Ensure(ctx, "admin", "", access.Stated(true), nil)
			if err != nil {
				t.Fatal(err)
			}
			admin = person.ID
			if _, err := db.DB.NewRaw(`INSERT INTO "admin_change" ("at", "by", "kind", "about", "became")`+
				` VALUES (?, ?, ?, ?, ?)`, time.Now().UTC(), admin, "setting", trailRows[0], "high").
				Exec(ctx); err != nil {
				t.Fatal(err)
			}
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			var rows []struct {
				Actor string `bun:"actor"`
				By    *int64 `bun:"by"`
			}
			if err := db.DB.NewRaw(`SELECT "actor", "by" FROM "admin_change" WHERE "about" IN (?)`,
				bun.List(trailRows)).Scan(ctx, &rows); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].Actor != "person" || rows[0].By == nil || *rows[0].By != admin {
				t.Errorf("upgraded, the trail reads %+v", rows)
			}
			if err := trail.NewStore(db.DB).RecordByConfiguration(ctx, trail.Account, trailRows[1],
				nil, trail.Said(trail.NamedInConfiguration, true)); err != nil {
				t.Fatalf("upgraded, configuration could not record a change: %v", err)
			}
		},
	}
}

// v0.5.0's declaration of each table it creates or changes is the table the
// chain of migrations builds, on every engine. SQLite builds a changed table
// from the declaration and the servers alter the table v0.4.0 built, so
// nothing else holds the two to each other. Each is built beside the real
// table under a scratch name and the two are described alike.
func theV050DeclarationsAreTheTablesTheMigrationsBuild() upgradeCheck {
	return upgradeCheck{
		name: "TheV050DeclarationsAreTheTablesTheMigrationsBuild",
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			declarationsAreBuilt(t, ctx, db, migrations.StatementsV050(db.Server.Engine), nil)
		},
	}
}
