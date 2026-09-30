// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"database/sql"
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

// A scan changes how the rows divide more than how many there are: a second
// build adds a tenth to the findings and a second value to the column they
// are divided by. The statistics have to follow that, not only growth.
func TestSQLiteStatisticsFollowANewValueAfterSmallGrowth(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		scratchTable(t, db, "divided", `"target" INTEGER, "n" INTEGER`)
		insert := func(target, rows int) {
			t.Helper()
			if _, err := db.ExecContext(ctx, `WITH RECURSIVE s(x) AS
				(SELECT 1 UNION ALL SELECT x + 1 FROM s WHERE x < ?)
				INSERT INTO "divided" SELECT ?, x FROM s`, rows, target); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.ExecContext(ctx, `CREATE INDEX "divided_target" ON "divided" ("target")`); err != nil {
			t.Fatal(err)
		}
		insert(1, 5000)
		if err := database.RefreshStatistics(ctx, db); err != nil {
			t.Fatal(err)
		}
		insert(2, 500)
		if err := database.RefreshStatistics(ctx, db); err != nil {
			t.Fatal(err)
		}
		var stat string
		if err := db.QueryRowContext(ctx,
			`SELECT "stat" FROM "sqlite_stat1" WHERE "idx" = 'divided_target'`).Scan(&stat); err != nil {
			t.Fatal(err)
		}
		if stat != "5500 2750" {
			t.Errorf("the statistics read %q after a second target arrived, want %q", stat, "5500 2750")
		}
	})
}

// A connection reads the statistics when it opens, so every connection open
// across a refresh has to be replaced before it plans again. Held at once so
// that none of them can be the same connection twice.
func TestEverySQLiteConnectionPlansFromRefreshedStatistics(t *testing.T) {
	db := sqliteFile(t)
	ctx := t.Context()
	for _, statement := range []string{
		`CREATE TABLE "skewed" ("a" INTEGER, "b" INTEGER, "c" INTEGER, "d" INTEGER)`,
		`CREATE INDEX "skewed_abc" ON "skewed" ("a", "b", "c")`,
		`CREATE INDEX "skewed_d" ON "skewed" ("d")`,
		`WITH RECURSIVE s(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM s WHERE x < 5000)
		 INSERT INTO "skewed" SELECT 1, 1, 1, x FROM s`,
	} {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	const held = 4
	plans := func() []string {
		t.Helper()
		conns := make([]*sql.Conn, 0, held)
		defer func() {
			for _, conn := range conns {
				_ = conn.Close()
			}
		}()
		var got []string
		for range held {
			conn, err := db.DB.DB.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			conns = append(conns, conn)
			var id, parent, unused int
			var detail string
			if err := conn.QueryRowContext(ctx, `EXPLAIN QUERY PLAN
				SELECT * FROM "skewed" WHERE "a" = 1 AND "b" = 1 AND "c" = 1 AND "d" = 42`).
				Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			got = append(got, detail)
		}
		return got
	}

	for _, plan := range plans() {
		if !strings.Contains(plan, "skewed_abc") {
			t.Fatalf("without statistics a connection planned %q, so this shape no longer shows the mistake", plan)
		}
	}
	if err := database.RefreshStatistics(ctx, db); err != nil {
		t.Fatal(err)
	}
	for i, plan := range plans() {
		if !strings.Contains(plan, "skewed_d") {
			t.Errorf("connection %d of %d planned %q after the refresh, from the statistics it opened with", i+1, held, plan)
		}
	}
}

func TestRefreshingStatisticsSucceedsOnEveryEngine(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if err := database.RefreshStatistics(t.Context(), db); err != nil {
			t.Error(err)
		}
	})
}
