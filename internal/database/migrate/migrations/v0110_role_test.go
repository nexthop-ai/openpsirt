// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A role a v0.10.0 database granted keeps its name across the upgrade, and
// every table holding a role then holds the longest role name there is. Too
// narrow, a server engine refuses the grant and SQLite takes it.
func TestEveryRoleColumnHoldsTheLongestRoleAfterTheV0110Upgrade(t *testing.T) {
	var longest access.Role
	for _, role := range access.Roles() {
		if len(role) > len(longest) {
			longest = role
		}
	}
	if longest == "" {
		t.Fatal("no role was found, so this checked nothing")
	}
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0100)
		declared, err := declareBeforeV0110(ctx, db)
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
		person, product := declared.Person.ID, declared.Product.ID
		exec(`INSERT INTO "role_grant" ("person_id", "product_id", "role", "source", "active", "created_at")
			VALUES (?, ?, ?, ?, ?, ?)`, person, product, access.PrivateTriage, access.Assigned, true, at)

		dbtest.MigrateTo(t, db, v0110)

		var kept string
		if err := db.DB.NewRaw(`SELECT "role" FROM "role_grant" WHERE "person_id" = ? AND "product_id" = ?`,
			person, product).Scan(ctx, &kept); err != nil {
			t.Fatal(err)
		}
		if kept != string(access.PrivateTriage) {
			t.Errorf("a grant of %s reads %q after the upgrade", access.PrivateTriage, kept)
		}
		exec(`INSERT INTO "role_grant" ("person_id", "product_id", "role", "source", "active", "created_at")
			VALUES (?, ?, ?, ?, ?, ?)`, person, product, longest, access.Assigned, true, at)
		exec(`INSERT INTO "role_grant_all" ("person_id", "role", "source", "active", "created_at")
			VALUES (?, ?, ?, ?, ?)`, person, longest, access.Assigned, true, at)
		exec(`INSERT INTO "group_role" ("group_name", "product_name", "role", "created_at")
			VALUES (?, ?, ?, ?)`, "analysts", "sonic", longest, at)
		exec(`INSERT INTO "group_role_all" ("group_name", "role", "created_at")
			VALUES (?, ?, ?)`, "analysts", longest, at)
		var held []string
		if err := db.DB.NewRaw(`SELECT "role" FROM "role_grant" WHERE "role" = ?
			UNION ALL SELECT "role" FROM "role_grant_all" WHERE "role" = ?
			UNION ALL SELECT "role" FROM "group_role" WHERE "role" = ?
			UNION ALL SELECT "role" FROM "group_role_all" WHERE "role" = ?`,
			longest, longest, longest, longest).Scan(ctx, &held); err != nil {
			t.Fatal(err)
		}
		if len(held) != 4 {
			t.Errorf("%d of the four role tables read %s back whole: %q", len(held), longest, held)
		}
		leaveAtLatest(t, ctx, db)
	})
}
