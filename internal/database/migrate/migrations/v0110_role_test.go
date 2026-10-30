// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// roleV0100 is the person and the product of a grant a v0.10.0 database
// holds.
type roleV0100 struct{ person, product int64 }

func seedRoleV0100(t *testing.T, ctx context.Context, db *database.DB) roleV0100 {
	t.Helper()
	declared := worldBeforeV0110(t, ctx, db)
	out := roleV0100{declared.Person.ID, declared.Product.ID}
	if _, err := db.DB.NewRaw(`INSERT INTO "role_grant" ("person_id", "product_id", "role", "source", "active",
		"created_at") VALUES (?, ?, ?, ?, ?, ?)`, out.person, out.product, access.PrivateTriage, access.Assigned,
		true, time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return out
}

// holdsTheLongest asserts the role the seed granted keeps its name across the
// upgrade, and every table holding a role then holds the longest role name
// there is. Too narrow, a server engine refuses the grant and SQLite takes it.
//
// The tables checked are the ones the migrated schema has a role column in,
// read from the database at the latest migration, so a table a later release
// adds fails here until it is given a row. SQLite takes any width, so there the
// comparison of the two sets is what fails. It migrates to the latest and
// writes a row to each table.
func (g roleV0100) holdsTheLongest(t *testing.T, ctx context.Context, db *database.DB) {
	t.Helper()
	var longest access.Role
	for _, role := range access.Roles() {
		if len(role) > len(longest) {
			longest = role
		}
	}
	if longest == "" {
		t.Fatal("no role was found, so this checked nothing")
	}
	if err := schema.Up(ctx, db, quiet()); err != nil {
		t.Fatalf("migrate to the latest: %v", err)
	}
	at := time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	person, product := g.person, g.product

	var kept string
	if err := db.DB.NewRaw(`SELECT "role" FROM "role_grant" WHERE "person_id" = ? AND "product_id" = ?`,
		person, product).Scan(ctx, &kept); err != nil {
		t.Fatal(err)
	}
	if kept != string(access.PrivateTriage) {
		t.Errorf("a grant of %s reads %q after the upgrade", access.PrivateTriage, kept)
	}

	rows := map[string]func(){
		"role_grant": func() {
			exec(`INSERT INTO "role_grant" ("person_id", "product_id", "role", "source", "active", "created_at")
				VALUES (?, ?, ?, ?, ?, ?)`, person, product, longest, access.Assigned, true, at)
		},
		"role_grant_all": func() {
			exec(`INSERT INTO "role_grant_all" ("person_id", "role", "source", "active", "created_at")
				VALUES (?, ?, ?, ?, ?)`, person, longest, access.Assigned, true, at)
		},
		"group_role": func() {
			exec(`INSERT INTO "group_role" ("group_name", "product_name", "role", "created_at")
				VALUES (?, ?, ?, ?)`, "analysts", "sonic", longest, at)
		},
		"group_role_all": func() {
			exec(`INSERT INTO "group_role_all" ("group_name", "role", "created_at")
				VALUES (?, ?, ?)`, "analysts", longest, at)
		},
	}
	holding := tablesWithColumn(describe(t, ctx, db), "role")
	if len(holding) == 0 {
		t.Fatal("no table in the migrated schema has a role column, so this checked nothing")
	}
	for _, table := range holding {
		if rows[table] == nil {
			t.Errorf("table %s has a role column and this test writes no row to it", table)
		}
	}
	for table := range rows {
		if !slices.Contains(holding, table) {
			t.Errorf("this test writes a role to %s, which has no role column", table)
		}
	}
	if t.Failed() {
		return
	}
	for _, table := range holding {
		rows[table]()
		var held int
		if err := db.DB.NewRaw(`SELECT COUNT(*) FROM ? WHERE "role" = ?`,
			bun.Ident(table), longest).Scan(ctx, &held); err != nil {
			t.Fatal(err)
		}
		if held != 1 {
			t.Errorf("%s reads %s back whole in %d rows, not one", table, longest, held)
		}
	}
}

// tablesWithColumn is each table a schema description has a column of this
// name in, sorted.
func tablesWithColumn(described []string, column string) []string {
	var tables []string
	for _, line := range described {
		rest, found := strings.CutPrefix(line, "column ")
		if !found {
			continue
		}
		name, _, _ := strings.Cut(rest, " ")
		table, col, _ := strings.Cut(name, ".")
		if col == column && !slices.Contains(tables, table) {
			tables = append(tables, table)
		}
	}
	slices.Sort(tables)
	return tables
}
