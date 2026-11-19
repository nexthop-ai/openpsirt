// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// An upgrade leaves no index on a table holding rows without statistics. On
// SQLite an index with none is preferred over one whose statistics show
// thousands of rows behind each key, so an upgrade adding or renaming an index
// beside analyzed ones turns a read of a second into one of minutes.
func TestAnUpgradeLeavesEveryIndexWithStatistics(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, v0120)
		// A node of a build: the upgrade adds indexes to the node table.
		scan := seedScanV0120(t, db)
		exec, id := seedSQL(ctx, db)
		exec(t, `INSERT INTO "component" ("identity", "name", "version", "name_folded", "fold_key", "first_seen_at")
			VALUES (?, ?, ?, ?, ?, ?)`, "c1", "openssl", "3.0.2", "openssl", "k1", time.Date(2026, 10, 20, 2, 0, 0, 0, time.UTC))
		component := id(t, `SELECT MAX("id") FROM "component"`)
		exec(t, `INSERT INTO "graph_node" ("build_id", "component_id", "is_root", "opened_scan_id")
			SELECT "build_id", ?, ?, "id" FROM "scan" WHERE "id" = ?`, component, true, scan)
		// What a start of the release left: statistics for its own schema.
		if err := database.RefreshStatistics(ctx, db); err != nil {
			t.Fatal(err)
		}
		if err := migrate.Up(ctx, db, quiet(), 0); err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		missing, examined := unanalyzedIndexes(t, ctx, db)
		if examined == 0 {
			t.Fatal("no index on a table holding rows was found, so this checked nothing")
		}
		if len(missing) > 0 {
			t.Errorf("after the upgrade these indexes on tables holding rows have no statistics: %v", missing)
		}
		leaveAtLatest(t, ctx, db)
	})
}

// unanalyzedIndexes names every index on a table holding rows that SQLite's
// statistics table has no row for, and counts the indexes it examined.
func unanalyzedIndexes(t *testing.T, ctx context.Context, db *database.DB) ([]string, int) {
	t.Helper()
	var indexes []struct {
		Table string `bun:"tbl_name"`
		Name  string `bun:"name"`
	}
	if err := db.NewRaw(`SELECT "tbl_name", "name" FROM "sqlite_master"
		WHERE "type" = 'index' ORDER BY "tbl_name", "name"`).Scan(ctx, &indexes); err != nil {
		t.Fatal(err)
	}
	var missing []string
	examined := 0
	for _, index := range indexes {
		var held int
		if err := db.NewRaw(`SELECT COUNT(*) FROM (SELECT 1 FROM ? LIMIT 1) AS "one"`,
			bun.Ident(index.Table)).Scan(ctx, &held); err != nil {
			t.Fatal(err)
		}
		if held == 0 {
			continue
		}
		examined++
		var described int
		if err := db.NewRaw(`SELECT COUNT(*) FROM "sqlite_stat1" WHERE "tbl" = ? AND "idx" = ?`,
			index.Table, index.Name).Scan(ctx, &described); err != nil {
			t.Fatal(err)
		}
		if described == 0 {
			missing = append(missing, index.Name)
		}
	}
	return missing, examined
}
