// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Upgraded, every issue v0.4.0 held is read as itself, and the two tables that
// record a merge exist and are empty.
func everyIssueIsReadAsItself() upgradeCheck {
	var issues []int64
	return upgradeCheck{
		name: "AV040DatabaseReadsEveryIssueAsItself",
		seed: func(t *testing.T, ctx context.Context, db *database.DB) {
			issues = nil
			for _, name := range []string{"CVE-2026-1", "GHSA-aaaa-bbbb-cccc"} {
				issues = append(issues, insertIssue(t, ctx, db, name))
			}
		},
		upgraded: func(t *testing.T, ctx context.Context, db *database.DB) {
			for _, id := range issues {
				var readAs int64
				if err := db.DB.NewRaw(`SELECT "issue_id" FROM "vulnerability" WHERE "id" = ?`, id).
					Scan(ctx, &readAs); err != nil {
					t.Fatalf("read issue %d: %v", id, err)
				}
				if readAs != id {
					t.Errorf("issue %d is read as %d, want itself", id, readAs)
				}
			}
			// Every issue, including those other checks wrote: v0.4.0 merged
			// nothing, so none of them is read as another.
			for _, row := range read(t, ctx, db, "vulnerability", []string{"id", "issue_id"}) {
				if row["issue_id"] != row["id"] {
					t.Errorf("issue %s is read as %s, want itself", row["id"], row["issue_id"])
				}
			}
			for _, table := range []string{"vulnerability_merge", "decision_superseded"} {
				if rows := read(t, ctx, db, table, []string{"id"}); len(rows) != 0 {
					t.Errorf("%s holds %d rows after the upgrade", table, len(rows))
				}
			}
		},
	}
}
