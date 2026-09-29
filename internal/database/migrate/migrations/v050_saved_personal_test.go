// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"database/sql"
	"strings"
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
		{"the grouping", "view=components&q=ssl", "q=ssl"},
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

// preparedRow is what one saved filter prepares, as the checks below read it.
type preparedRow struct {
	display, outcome, justification, reasoning string
	days                                       int64
}

// longProduct is a product display name longer than a filter name may be.
var longProduct = strings.Repeat("L", 150)

// longName is a filter name as long as the endpoints take one.
var longName = strings.Repeat("n", 118)

// Upgraded, a saved filter is its person's and keeps no scope. One name kept
// in several products stays with the oldest, and each other is renamed after
// its product, numbered past a name the person already holds, and cut to the
// width the endpoints take a name at. One that is an older one's twin once its
// scope is gone is dropped. A name held once is left alone, and so is another
// person's filter of the same name. The name is unique to the person. Rolled
// back, each filter is kept in every product, under the name the upgrade left
// it and with the claim it prepares.
func savedFiltersBecomeTheirPersons() upgradeCheck {
	var ana, bo int64
	ids := map[string]int64{}
	claim := preparedRow{"Claim", "deferred", "", "Waiting on the next kernel bump.", 90}
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
				"saved-core": "Core", "saved-long": longProduct,
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
				prepares       *preparedRow
			}{
				// Written before the oldest, so the oldest keeps the name by
				// its age rather than by its identifier.
				{"renamed", ana, "kernel", "Kernel", "saved-switch", "fixable=1", 1, nil},
				{"kept", ana, "kernel", "kernel", "saved-router", "stream=main&variant=x86&exploited=1", 0, nil},
				// Its product's rename is held already, so it is numbered.
				{"numbered", ana, "kernel", "", "saved-edge", "q=ssl", 2, nil},
				{"already", ana, "kernel (saved-edge)", "kernel (saved-edge)", "saved-router", "", 3, nil},
				// The oldest's query on another branch, preparing nothing
				// either: the same filter twice once the branch goes.
				{"twin", ana, "kernel", "kernel", "saved-core", "stream=master&exploited=1", 6, nil},
				// Renamed after a product whose name is longer than a filter's
				// may be.
				{"long", ana, "kernel", "kernel", "saved-long", "severity=high", 7, nil},
				// A name as long as a filter's may be, renamed within that width.
				{"wide", ana, longName, longName, "saved-router", "q=a", 9, nil},
				{"narrowed", ana, longName, longName, "saved-switch", "q=b", 10, nil},
				// Held once: its scope and grouping go and its name stays.
				{"alone", ana, "lonely", "Lonely", "saved-switch",
					"beneath=zlib&beneath_version=1.2&q=ssl&opened_by_run=4&differs=1&variants=only&view=components&sort=age",
					4, nil},
				// Another person's name is not a clash.
				{"theirs", bo, "kernel", "kernel", "saved-switch", "state=undecided", 5, nil},
				{"claim", ana, "claim", "Claim", "saved-router", "component=linux", 8, &claim},
			} {
				prepares := row.prepares
				if prepares == nil {
					prepares = &preparedRow{}
				}
				if _, err := db.DB.NewRaw(`INSERT INTO "saved_filter"
					("person_id", "name", "display_name", "product_id", "query", "created_at",
					 "outcome", "justification", "reasoning", "defer_days")
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, row.person, row.name,
					sql.NullString{String: row.display, Valid: row.display != ""},
					products[row.product], row.query, at.AddDate(0, 0, row.days),
					sql.NullString{String: prepares.outcome, Valid: prepares.outcome != ""},
					sql.NullString{String: prepares.justification, Valid: prepares.justification != ""},
					sql.NullString{String: prepares.reasoning, Valid: prepares.reasoning != ""},
					sql.NullInt64{Int64: prepares.days, Valid: prepares.days != 0}).Exec(ctx); err != nil {
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
			long := "kernel (" + longProduct[:60] + ")"
			want := map[string]keptRow{
				"kept":     {"kernel", "kernel", "exploited=1"},
				"renamed":  {"kernel (switch)", "Kernel (Switch)", "fixable=1"},
				"numbered": {"kernel (saved-edge) 2", "kernel (saved-edge) 2", "q=ssl"},
				"already":  {"kernel (saved-edge)", "kernel (saved-edge)", ""},
				"long":     {strings.ToLower(long), long, "severity=high"},
				"alone":    {"lonely", "Lonely", "q=ssl&sort=age"},
				"theirs":   {"kernel", "kernel", "state=undecided"},
				"claim":    {"claim", "Claim", "component=linux"},
				"wide":     {longName, longName, "q=a"},
				"narrowed": {longName[:111] + " (switch)", longName[:111] + " (Switch)", "q=b"},
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
			var twins int
			if err := db.DB.NewRaw(`SELECT COUNT(*) FROM "saved_filter" WHERE "id" = ?`, ids["twin"]).
				Scan(ctx, &twins); err != nil {
				t.Fatal(err)
			}
			if twins != 0 {
				t.Error("upgraded, a filter that is an older one's twin once its branch is gone is kept")
			}
			if got := preparedBy(t, ctx, db, `"id" = ?`, ids["claim"]); len(got) != 1 || got[0] != claim {
				t.Errorf("upgraded, the filter preparing a claim prepares %+v, want %+v", got, claim)
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
				{ana, "kernel (saved-edge)"}, {ana, strings.ToLower("kernel (" + longProduct[:60] + ")")},
				{ana, "lonely"}, {ana, "claim"}, {bo, "kernel"},
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
			for _, got := range preparedBy(t, ctx, db, `"person_id" = ? AND "name" = 'claim'`, ana) {
				if got != claim {
					t.Errorf("rolled back, the filter preparing a claim prepares %+v, want %+v", got, claim)
				}
			}
		},
	}
}

// preparedBy reads what each saved filter matching a condition prepares.
func preparedBy(t *testing.T, ctx context.Context, db *database.DB, where string, arg int64) []preparedRow {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT "display_name", "outcome", "justification",
		"reasoning", "defer_days" FROM "saved_filter" WHERE `+where, arg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []preparedRow
	for rows.Next() {
		var display, outcome, justification, reasoning sql.NullString
		var days sql.NullInt64
		if err := rows.Scan(&display, &outcome, &justification, &reasoning, &days); err != nil {
			t.Fatal(err)
		}
		out = append(out, preparedRow{display.String, outcome.String, justification.String,
			reasoning.String, days.Int64})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
