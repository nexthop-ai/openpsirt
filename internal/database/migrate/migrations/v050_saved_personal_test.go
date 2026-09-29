// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

// A kept query loses the words saying where the list is, and keeps every
// other parameter exactly as written.
func TestAKeptQueryLosesItsScope(t *testing.T) {
	for _, each := range []struct{ name, kept, want string }{
		{"a branch and a variant", "stream=main&exploited=1&variant=x86", "exploited=1"},
		{"a subtree of one build", "beneath=zlib&beneath_version=1.2&beneath_ecosystem=deb&beneath_namespace=debian&q=ssl",
			"q=ssl"},
		{"what differs and what is spread over variants", "differs=1&variants=only&sort=age", "sort=age"},
		{"the run that opened it", "opened_by_run=7&state=undecided", "state=undecided"},
		{"an escaped word", "str%65am=main&hide=a%7Eb", "hide=a%7Eb"},
		{"nothing but scope", "stream=main&variant=x86", ""},
		{"no scope", "state=undecided&state=agreed&q=a+b", "state=undecided&state=agreed&q=a+b"},
		{"a word it cannot read", "%zz=1&stream=main", "%zz=1"},
		{"nothing", "", ""},
	} {
		t.Run(each.name, func(t *testing.T) {
			if got := migrations.Unscoped(each.kept); got != each.want {
				t.Errorf("%q became %q, want %q", each.kept, got, each.want)
			}
		})
	}
}

// keptRow is one saved filter as the checks below read it.
type keptRow struct {
	name, display, query string
}

// Upgraded, a saved filter is its person's and keeps no scope. One name kept
// in several products stays with the oldest, and each other is renamed after
// its product, numbered past a name the person already holds. A name held once
// is left alone, and so is another person's filter of the same name. The name
// is unique to the person. Rolled back, each filter is kept in every product,
// under the name the upgrade left it.
func savedFiltersBecomeTheirPersons() upgradeCheck {
	var ana, bo int64
	ids := map[string]int64{}
	return upgradeCheck{
		name: "AnUpgradeMakesSavedFiltersTheirPersonsAndDropsTheirScope",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			people := access.NewStore(db.DB)
			for identity, id := range map[string]*int64{"saved-ana": &ana, "saved-bo": &bo} {
				person, err := people.Ensure(ctx, identity, "", access.Stated(false), nil)
				if err != nil {
					t.Fatal(err)
				}
				*id = person.ID
			}
			at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
			products := map[string]int64{}
			for name, display := range map[string]string{
				"saved-router": "Router", "saved-switch": "Switch", "saved-edge": "",
			} {
				if _, err := db.DB.NewRaw(`INSERT INTO "product" ("name", "display_name", "created_at")
					VALUES (?, ?, ?)`, name, display, at).Exec(ctx); err != nil {
					t.Fatal(err)
				}
				var id int64
				if err := db.DB.NewRaw(`SELECT "id" FROM "product" WHERE "name" = ?`, name).
					Scan(ctx, &id); err != nil {
					t.Fatal(err)
				}
				products[name] = id
			}
			for _, row := range []struct {
				key            string
				person         int64
				name, display  string
				product, query string
				days           int
			}{
				// The oldest of three holding one name keeps it.
				{"kept", ana, "kernel", "kernel", "saved-router", "stream=main&variant=x86&exploited=1", 0},
				{"renamed", ana, "kernel", "Kernel", "saved-switch", "fixable=1", 1},
				// Its product's rename is held already, so it is numbered.
				{"numbered", ana, "kernel", "", "saved-edge", "q=ssl", 2},
				{"already", ana, "kernel (saved-edge)", "kernel (saved-edge)", "saved-router", "", 3},
				// Held once: its scope goes and its name stays.
				{"alone", ana, "lonely", "Lonely", "saved-switch",
					"beneath=zlib&beneath_version=1.2&q=ssl&opened_by_run=4&differs=1&variants=only&sort=age", 4},
				// Another person's name is not a clash.
				{"theirs", bo, "kernel", "kernel", "saved-switch", "state=undecided", 5},
			} {
				if _, err := db.DB.NewRaw(`INSERT INTO "saved_filter"
					("person_id", "name", "display_name", "product_id", "query", "created_at")
					VALUES (?, ?, ?, ?, ?, ?)`, row.person, row.name,
					sql.NullString{String: row.display, Valid: row.display != ""},
					products[row.product], row.query, at.AddDate(0, 0, row.days)).Exec(ctx); err != nil {
					t.Fatal(err)
				}
				var id int64
				if err := db.DB.NewRaw(`SELECT "id" FROM "saved_filter"
					WHERE "person_id" = ? AND "product_id" = ? AND "name" = ?`,
					row.person, products[row.product], row.name).Scan(ctx, &id); err != nil {
					t.Fatal(err)
				}
				ids[row.key] = id
			}
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			want := map[string]keptRow{
				"kept":     {"kernel", "kernel", "exploited=1"},
				"renamed":  {"kernel (switch)", "Kernel (Switch)", "fixable=1"},
				"numbered": {"kernel (saved-edge) 2", "kernel (saved-edge) 2", "q=ssl"},
				"already":  {"kernel (saved-edge)", "kernel (saved-edge)", ""},
				"alone":    {"lonely", "Lonely", "q=ssl&sort=age"},
				"theirs":   {"kernel", "kernel", "state=undecided"},
			}
			for key, row := range want {
				var got keptRow
				var display sql.NullString
				if err := db.DB.NewRaw(`SELECT "name", "display_name", "query" FROM "saved_filter"
					WHERE "id" = ?`, ids[key]).Scan(ctx, &got.name, &display, &got.query); err != nil {
					t.Fatalf("read %s: %v", key, err)
				}
				got.display = display.String
				if got != row {
					t.Errorf("upgraded, %s is %+v, want %+v", key, got, row)
				}
			}
			if err := db.DB.NewRaw(`SELECT "product_id" FROM "saved_filter"`).Scan(ctx, new(int64)); err == nil {
				t.Error("upgraded, a saved filter still names a product")
			}
			// One name per person: a second "lonely" is refused.
			if _, err := db.DB.NewRaw(`INSERT INTO "saved_filter"
				("person_id", "name", "query", "created_at") VALUES (?, ?, ?, ?)`,
				ana, "lonely", "", time.Now().UTC().Truncate(time.Microsecond)).Exec(ctx); !database.IsDuplicate(err) {
				t.Errorf("upgraded, a second filter of one name for one person is %v, want refused as a duplicate", err)
			}
		},
		rolledBack: func(t *testing.T, ctx context.Context, db *database.DB) {
			var products int
			if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "product"`).Scan(ctx, &products); err != nil {
				t.Fatal(err)
			}
			for _, each := range []struct {
				person int64
				name   string
			}{
				{ana, "kernel"}, {ana, "kernel (switch)"}, {ana, "kernel (saved-edge) 2"},
				{ana, "kernel (saved-edge)"}, {ana, "lonely"}, {bo, "kernel"},
			} {
				var in, distinct int
				if err := db.DB.NewRaw(`SELECT COUNT(*), COUNT(DISTINCT "product_id") FROM "saved_filter"
					WHERE "person_id" = ? AND "name" = ?`, each.person, each.name).
					Scan(ctx, &in, &distinct); err != nil {
					t.Fatal(err)
				}
				if in != products || distinct != products {
					t.Errorf("rolled back, %q is kept %d times in %d products, want once in each of %d",
						each.name, in, distinct, products)
				}
			}
		},
	}
}
