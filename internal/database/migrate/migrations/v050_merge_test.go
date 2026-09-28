// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// Upgraded, every issue v0.4.0 held is read as itself, and the two tables that
// record a merge exist and are empty. Rolled back, the column and the tables
// are gone and the issues are as v0.4.0 held them.
func TestAV040DatabaseReadsEveryIssueAsItself(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rollBack(t, ctx, db)
		dbtest.MigrateTo(t, db, v030)
		built := describe(t, ctx, db)

		now := time.Now().UTC().Truncate(time.Second)
		for _, name := range []string{"CVE-2026-1", "GHSA-aaaa-bbbb-cccc"} {
			if _, err := db.DB.NewRaw(`INSERT INTO "vulnerability" ("identifier", "identifier_folded",
				"exploited", "first_seen_at") VALUES (?, ?, ?, ?)`,
				name, name, false, now).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		dbtest.MigrateTo(t, db, v050)
		issues := read(t, ctx, db, "vulnerability", []string{"id", "issue_id"})
		if len(issues) != 2 {
			t.Fatalf("%d issues came across, want 2", len(issues))
		}
		for _, row := range issues {
			if row["issue_id"] != row["id"] {
				t.Errorf("issue %s is read as %s, want itself", row["id"], row["issue_id"])
			}
		}
		for _, table := range []string{"vulnerability_merge", "decision_superseded"} {
			if rows := read(t, ctx, db, table, []string{"id"}); len(rows) != 0 {
				t.Errorf("%s holds %d rows after the upgrade", table, len(rows))
			}
		}

		if err := schema.Down(ctx, db, quiet()); err != nil {
			t.Fatalf("roll the upgrade back: %v", err)
		}
		if diff := setDiff(built, describe(t, ctx, db)); diff != "" {
			t.Errorf("rolled back, the schema differs from v0.4.0's:\n%s", diff)
		}
		if got := read(t, ctx, db, "vulnerability", []string{"id"}); len(got) != 2 {
			t.Errorf("rolled back, %d issues are left, want 2", len(got))
		}
		leaveAtLatest(t, ctx, db)
	})
}
