// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// seedRuns counts how many times the probe seed ran on each engine.
var (
	seedRunsMu sync.Mutex
	seedRuns   = map[database.Engine]int{}
)

// probe seeds one product and hands back its identifier, which is what a
// seed is for: a test reaches what was seeded through what the seed made.
var probe = dbtest.Seed(func(ctx context.Context, db *database.DB) (int64, error) {
	seedRunsMu.Lock()
	seedRuns[db.Server.Engine]++
	seedRunsMu.Unlock()
	// Seeding is written so that a database the harness failed to empty
	// still seeds, and the test that copies it is what reports the rows the
	// previous test left. A seed that refused a duplicate would fail first,
	// for a reason that names the constraint rather than the leak.
	var id int64
	err := db.NewSelect().TableExpr(`"product"`).ColumnExpr(`"id"`).
		Where(`"name" = 'seeded'`).Scan(ctx, &id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO "product" ("name", "display_name", "created_at") VALUES ('seeded', 'Seeded', ?)`,
		time.Now().UTC()); err != nil {
		return 0, err
	}
	err = db.NewSelect().TableExpr(`"product"`).ColumnExpr(`"id"`).
		Where(`"name" = 'seeded'`).Scan(ctx, &id)
	return id, err
})

func TestASeededTemplateGivesEveryTestTheSeedAndNothingATestAdded(t *testing.T) {
	// Two tests start from the seed. Each sees the seeded row under the
	// identifier the seed returned, adds a row of its own, and never sees the
	// other's: on SQLite each holds a copy of the seeded template, and on a
	// server the database is emptied and seeded again between them.
	//
	// Grouped under one subtest so that the count below runs after both,
	// because on SQLite they run beside each other and the enclosing function
	// would otherwise reach the count first.
	engines := map[database.Engine]bool{}
	var enginesMu sync.Mutex
	t.Run("two tests from one seed", func(t *testing.T) {
		for _, name := range []string{"first", "second"} {
			t.Run(name, func(t *testing.T) {
				probe.Each(t, func(t *testing.T, db *database.DB, seeded int64) {
					ctx := t.Context()
					enginesMu.Lock()
					engines[db.Server.Engine] = true
					enginesMu.Unlock()

					var got string
					if err := db.NewSelect().TableExpr(`"product"`).ColumnExpr(`"name"`).
						Where(`"id" = ?`, seeded).Scan(ctx, &got); err != nil {
						t.Fatalf("the seeded product is not at the identifier the seed returned: %v", err)
					}
					if got != "seeded" {
						t.Fatalf("product %d is %q, want the seeded one", seeded, got)
					}

					var others int
					if err := db.NewSelect().TableExpr(`"product"`).ColumnExpr(`count(*)`).
						Where(`"name" <> 'seeded'`).Scan(ctx, &others); err != nil {
						t.Fatal(err)
					}
					if others != 0 {
						t.Fatalf("%d products besides the seeded one: a test's rows reached another test", others)
					}
					if _, err := db.ExecContext(ctx,
						`INSERT INTO "product" ("name", "display_name", "created_at") VALUES (?, ?, ?)`,
						name, name, time.Now().UTC()); err != nil {
						t.Fatal(err)
					}
				})
			})
		}
	})

	if len(engines) == 0 {
		t.Fatal("no engine ran, so this checked nothing")
	}
	seedRunsMu.Lock()
	defer seedRunsMu.Unlock()
	for engine := range engines {
		want := 2
		if engine == database.SQLite {
			// Once per binary, however many tests copy it.
			want = 1
		}
		if got := seedRuns[engine]; got != want {
			t.Errorf("the seed ran %d times on %s, want %d", got, engine, want)
		}
	}
}
