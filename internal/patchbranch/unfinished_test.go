// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// A visit records itself as unfinished while it runs, so one whose process
// is killed part way waits out a day like any failure, rather than being
// chosen first on restart and killing the process again. The report reads it
// as under way while a replica holds the lease, and as failed once none does.
func TestAVisitTheProcessDidNotSurviveWaitsOutADay(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		made := project(t)
		issue(t, db, "CVE-2025-0201", "critical", link("killed", made.fix))
		var during string
		pass := patchbranch.NewLocalPass(db.DB, t.TempDir(), patchbranch.DefaultQuota, outward.Excluded{},
			func(string) string {
				if err := db.DB.NewSelect().Table("patch_repository").Column("failed").
					Where(`"url" = ?`, repositoryOf("killed")).Scan(ctx, &during); err != nil {
					t.Error(err)
				}
				return made.dir
			})
		if visited, err := pass.Once(ctx); err != nil || visited == "" {
			t.Fatalf("visited %q: %v", visited, err)
		}
		if during != patchbranch.Unfinished {
			t.Errorf("a visit under way recorded %q, want it unfinished", during)
		}

		// Put back to a visit begun a minute ago and never ended, its commit
		// due again, as a killed process leaves it.
		for _, change := range []struct{ table, set, where string }{
			{"patch_repository", `"failed" = '` + patchbranch.Unfinished + `'`, `"url" = ?`},
			{"patch_commit", `"looked_at" = NULL`,
				`"repository_id" IN (SELECT "id" FROM "patch_repository" WHERE "url" = ?)`},
		} {
			if _, err := db.DB.NewUpdate().Table(change.table).Set(change.set).
				Where(change.where, repositoryOf("killed")).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.DB.NewUpdate().Table("patch_repository").
			Set(`"fetched_at" = ?`, time.Now().UTC().Add(-time.Minute)).
			Set(`"reached_at" = ?`, time.Now().UTC().Add(-time.Hour)).
			Where(`"url" = ?`, repositoryOf("killed")).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if visited, err := pass.Once(ctx); err != nil || visited != "" {
			t.Errorf("a visit the process did not survive was chosen again: %q %v", visited, err)
		}

		state := func() patchbranch.State {
			t.Helper()
			repositories, _, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
			if err != nil || len(repositories) != 1 {
				t.Fatalf("the report lists %+v: %v", repositories, err)
			}
			return repositories[0].State
		}
		if got := state(); got != patchbranch.Failed {
			t.Errorf("with no lease held the report reads %s, want failed", got)
		}
		if _, err := queue.NewLeases(db.DB).Take(ctx, patchbranch.Lease, "another", time.Hour); err != nil {
			t.Fatal(err)
		}
		if got := state(); got != patchbranch.Working {
			t.Errorf("with the lease held the report reads %s, want under way", got)
		}
	})
}
