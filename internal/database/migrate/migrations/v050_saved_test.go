// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// A kept query is rewritten one parameter at a time, and a parameter the
// rewrite does not name is kept exactly as written.
func TestAKeptQueryIsRewrittenIntoTheWordsTheListReads(t *testing.T) {
	for _, each := range []struct{ name, kept, want string }{
		{"exploited", "only=exploited&state=undecided", "exploited=1&state=undecided"},
		{"fix available", "sort=age&only=hasFix", "sort=age&fixable=1"},
		{"a word that narrowed nothing", "only=soon&q=openssl", "q=openssl"},
		{"hidden names joined", "hide=zlib%2C+openssl%2C%2Clibc", "hide=zlib&hide=openssl&hide=libc"},
		{"hidden names joined unescaped", "hide=a,b", "hide=a&hide=b"},
		{"a name the list escapes its own way", "hide=a%7Eb%2Cc*d", "hide=a%7Eb&hide=c*d"},
		{"a flag already there", "exploited=1&only=exploited", "exploited=1"},
		{"a hidden name already there", "hide=zlib&hide=zlib%2Copenssl", "hide=zlib&hide=openssl"},
		{"a repeated parameter it does not name", "state=undecided&state=undecided", "state=undecided&state=undecided"},
		{"a value it cannot read", "only=%zz&q=x", "only=%zz&q=x"},
		{"a single hidden name", "hide=zlib", "hide=zlib"},
		{"nothing", "", ""},
	} {
		t.Run(each.name, func(t *testing.T) {
			if got := migrations.Respelled(each.kept); got != each.want {
				t.Errorf("%q became %q, want %q", each.kept, got, each.want)
			}
		})
	}
}

// Upgraded, every kept filter reads in the words v0.5.0's list takes, and one
// already in them is left alone. Rolled back, it stays in those words, which
// v0.4.0's list reads too.
func TestAnUpgradeRewritesKeptFiltersIntoTheWordsTheListReads(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)

		at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		person, err := access.NewStore(db.DB).Ensure(ctx, "ana", "", access.Stated(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewRaw(`INSERT INTO "product"
			("name", "display_name", "created_at") VALUES (?, ?, ?)`, "router", "Router", at).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		var product int64
		if err := db.DB.NewRaw(`SELECT "id" FROM "product" WHERE "name" = ?`, "router").
			Scan(ctx, &product); err != nil {
			t.Fatal(err)
		}
		for name, query := range map[string]string{
			"old":     "only=exploited&hide=zlib%2Copenssl",
			"current": "fixable=1&hide=zlib",
		} {
			if _, err := db.DB.NewRaw(`INSERT INTO "saved_filter"
				("person_id", "name", "product_id", "query", "created_at") VALUES (?, ?, ?, ?, ?)`,
				person.ID, name, product, query, at).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		dbtest.MigrateTo(t, db, v050)
		want := map[string]string{
			"old":     "exploited=1&hide=zlib&hide=openssl",
			"current": "fixable=1&hide=zlib",
		}
		for name, query := range want {
			if got := keptQuery(t, db, name); got != query {
				t.Errorf("upgraded, %s reads %q, want %q", name, got, query)
			}
		}

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		for name, query := range want {
			if got := keptQuery(t, db, name); got != query {
				t.Errorf("rolled back, %s reads %q, want %q", name, got, query)
			}
		}
		leaveAtLatest(t, ctx, db)
	})
}

func keptQuery(t *testing.T, db *database.DB, name string) string {
	t.Helper()
	var query string
	if err := db.DB.NewRaw(`SELECT "query" FROM "saved_filter" WHERE "name" = ?`, name).
		Scan(t.Context(), &query); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return query
}
