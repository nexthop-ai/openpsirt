// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A test arrives to an empty database whatever the test before it left, on
// every engine, with no Reset of its own. On a server every test in a package
// shares one database, so the harness empties it before each test.
//
// Verified by deleting the clear before fn in run: on each server the second
// subtest then counts the first one's row.
func TestATestArrivesToAnEmptyDatabase(t *testing.T) {
	const name = "dbtest.left-behind"
	t.Run("leaves a row", func(t *testing.T) {
		Each(t, func(t *testing.T, db *database.DB) {
			if _, err := db.ExecContext(t.Context(),
				`INSERT INTO "application_setting" ("name", "value", "updated_at") VALUES (?, ?, ?)`,
				name, "left by the test before", time.Now().UTC()); err != nil {
				t.Fatalf("leave a row: %v", err)
			}
		})
	})
	t.Run("finds none", func(t *testing.T) {
		Each(t, func(t *testing.T, db *database.DB) {
			var rows int
			if err := db.QueryRowContext(t.Context(),
				`SELECT COUNT(*) FROM "application_setting"`).Scan(&rows); err != nil {
				t.Fatalf("count the rows: %v", err)
			}
			if rows != 0 {
				t.Errorf("the test found %d row(s) the test before it left", rows)
			}
		})
	})
}
