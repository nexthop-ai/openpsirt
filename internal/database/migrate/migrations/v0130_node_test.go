// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
)

// seedNodeV0120 seeds a v0.12.0 build holding one component, and answers its
// node.
func seedNodeV0120(t *testing.T, db *database.DB) int64 {
	t.Helper()
	ctx := t.Context()
	scan := seedScanV0120(t, db)
	var build int64
	if err := db.DB.NewRaw(`SELECT "build_id" FROM "scan" WHERE "id" = ?`, scan).Scan(ctx, &build); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.DB.NewRaw(query, args...).Exec(ctx); err != nil {
			t.Fatalf("%v\n%s", err, query)
		}
	}
	exec(`INSERT INTO "component" ("identity", "purl", "name", "version", "fold_key", "first_seen_at")
		VALUES (?, ?, ?, ?, ?, ?)`, "c1", "pkg:deb/debian/zlib1g@1.3", "zlib1g", "1.3", "zlib1g", at)
	var component, node int64
	if err := db.DB.NewRaw(`SELECT MAX("id") FROM "component"`).Scan(ctx, &component); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO "graph_node" ("build_id", "component_id", "is_root", "opened_scan_id")
		VALUES (?, ?, ?, ?)`, build, component, false, scan)
	if err := db.DB.NewRaw(`SELECT MAX("id") FROM "graph_node"`).Scan(ctx, &node); err != nil {
		t.Fatal(err)
	}
	return node
}

// A v0.12.0 database's graph nodes gain the name and version a build stated
// and the folds of the name and the stated source, empty on every node already held, whether the upgrade
// ran whole or a start of it stopped after the first column or before the
// index.
func nodePartV0130() partV0130 {
	return partV0130{
		name: "ANodeHeldBeforeTheUpgradeStatesNothing",
		seed: func(t *testing.T, db *database.DB) func(t *testing.T) {
			node := seedNodeV0120(t, db)
			return func(t *testing.T) {
				var stated struct {
					Name    *string `bun:"name"`
					Version *string `bun:"version"`
					Folded  *string `bun:"name_folded"`
					Source  *string `bun:"source_folded"`
				}
				if err := db.DB.NewRaw(`SELECT "name", "version", "name_folded", "source_folded" FROM "graph_node" WHERE "id" = ?`, node).
					Scan(t.Context(), &stated); err != nil {
					t.Fatal(err)
				}
				if stated.Name != nil || stated.Version != nil || stated.Folded != nil || stated.Source != nil {
					t.Errorf("a node held before the upgrade states %v, %v, %v and %v, want none",
						stated.Name, stated.Version, stated.Folded, stated.Source)
				}
			}
		},
		stops: []stopV0130{
			{"after the name", func(t *testing.T, db *database.DB) error {
				return migrations.StopV0130AfterNodeName(t.Context(), db)
			}},
			{"before the index", func(t *testing.T, db *database.DB) error {
				return migrations.StopV0130BeforeNodeIndex(t.Context(), db)
			}},
		},
	}
}
