// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// keptRow is a row of a table with a bounded key, written through the insert
// that leaves another writer's row alone.
type keptRow struct {
	bun.BaseModel `bun:"table:application_setting"`

	Name      string    `bun:"name,pk"`
	Value     string    `bun:"value,notnull"`
	UpdatedAt time.Time `bun:"updated_at,notnull"`
}

// An insert that leaves alone a row another writer got to first skips that
// row and nothing else. A value wider than its column is refused as it is by
// an ordinary insert, on every engine that bounds widths, rather than being
// cut to fit and reported as written.
func TestKeepingAnotherWritersRowSkipsOnlyTheDuplicate(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Second)

		first := []keptRow{{Name: "kept", Value: "first", UpdatedAt: now}}
		if err := database.InBatchesKeeping(ctx, db, first); err != nil {
			t.Fatalf("the first write: %v", err)
		}
		again := []keptRow{{Name: "kept", Value: "second", UpdatedAt: now}}
		if err := database.InBatchesKeeping(ctx, db, again); err != nil {
			t.Fatalf("a row another writer got to first was refused: %v", err)
		}
		held := new(keptRow)
		if err := db.NewSelect().Model(held).Where(`"name" = ?`, "kept").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if held.Value != "first" {
			t.Errorf("the row holds %q, want the first writer's", held.Value)
		}

		if db.Server.Engine == database.SQLite {
			return // A declared width is not enforced here.
		}
		wide := []keptRow{{Name: strings.Repeat("w", 300), Value: "v", UpdatedAt: now}}
		if err := database.InBatchesKeeping(ctx, db, wide); err == nil {
			t.Error("a key wider than its column was written without an error")
		}
	})
}
