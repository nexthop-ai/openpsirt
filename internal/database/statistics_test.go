// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// The shape of a finding table under one large component: three columns that
// are nearly the same for every row, indexed together, beside one that is
// nearly unique. Without statistics SQLite takes the index matching more
// equalities and walks every row under it.
func TestSQLiteChoosesAnIndexByTheRowsBehindItOnceStatisticsAreRefreshed(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		scratchTable(t, db, "skewed", `"a" INTEGER, "b" INTEGER, "c" INTEGER, "d" INTEGER`)
		for _, statement := range []string{
			`CREATE INDEX "skewed_abc" ON "skewed" ("a", "b", "c")`,
			`CREATE INDEX "skewed_d" ON "skewed" ("d")`,
			`WITH RECURSIVE s(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM s WHERE x < 5000)
			 INSERT INTO "skewed" SELECT 1, 1, 1, x FROM s`,
		} {
			if _, err := db.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		plan := func() string {
			rows, err := db.QueryContext(ctx, `EXPLAIN QUERY PLAN
				SELECT * FROM "skewed" WHERE "a" = 1 AND "b" = 1 AND "c" = 1 AND "d" = 42`)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = rows.Close() }()
			var steps []string
			for rows.Next() {
				var id, parent, unused int
				var detail string
				if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
					t.Fatal(err)
				}
				steps = append(steps, detail)
			}
			return strings.Join(steps, "; ")
		}

		if before := plan(); !strings.Contains(before, "skewed_abc") {
			t.Fatalf("without statistics the plan is %q, so this shape no longer shows the mistake", before)
		}
		if err := database.RefreshStatistics(ctx, db); err != nil {
			t.Fatal(err)
		}
		if after := plan(); !strings.Contains(after, "skewed_d") {
			t.Errorf("after refreshing the statistics the plan is %q, want the index on the column that is nearly unique", after)
		}
	})
}

func TestRefreshingStatisticsSucceedsOnEveryEngine(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if err := database.RefreshStatistics(t.Context(), db); err != nil {
			t.Error(err)
		}
	})
}
