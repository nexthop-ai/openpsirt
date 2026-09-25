// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
)

func TestAWakeVisitsEveryRepositoryDueBeforeItSleeps(t *testing.T) {
	// A small visit takes about a second, so a wait between visits is what
	// kept the pass asleep: one repository per wake put the kernel hours
	// behind copies that took a second each.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		first, second, third := project(t), project(t), project(t)
		issue(t, db, "CVE-2025-0101", "high", link("first", first.fix))
		issue(t, db, "CVE-2025-0102", "medium", link("second", second.fix))
		issue(t, db, "CVE-2025-0103", "low", link("third", third.fix))
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"first": first, "second": second, "third": third})
		if visits := pass.Cycle(ctx); visits != 3 {
			t.Fatalf("one wake visited %d repositories, want all three that were due", visits)
		}
		if visits := pass.Cycle(ctx); visits != 0 {
			t.Errorf("a wake with nothing due visited %d, want it to go back to sleep", visits)
		}
	})
}

func TestProgressListsTheVisitUnderWayFirstWithHowFarItHasGot(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		empty(t, db)
		ctx := t.Context()
		busy, later := project(t), project(t)
		issue(t, db, "CVE-2025-0111", "low", link("busy", busy.fix), link("busy", busy.backport))
		issue(t, db, "CVE-2025-0112", "critical", link("later", later.fix))
		pass := passOver(t, db, patchbranch.DefaultQuota, outward.Excluded{},
			map[string]upstream{"busy": busy, "later": later})
		if visits := pass.Cycle(ctx); visits != 2 {
			t.Fatalf("visited %d repositories, want both", visits)
		}
		// The first put back to the middle of a visit: begun and not
		// finished, one commit looked up since it began and one still due.
		// The second put back to never visited, so it waits in the plan.
		// Scoped to the repository as well as the hash: two projects made in
		// the same second share their commits' hashes.
		for _, change := range []struct {
			table, set, repository, hash string
		}{
			{"patch_repository", "reached_at = NULL", "busy", ""},
			{"patch_commit", "looked_at = NULL", "busy", busy.backport},
			{"patch_commit", "looked_at = NULL", "later", later.fix},
			{"patch_repository", "reached_at = NULL", "later", ""},
			{"patch_repository", "fetched_at = NULL", "later", ""},
		} {
			update := db.DB.NewUpdate().Table(change.table).Set(change.set)
			if change.hash == "" {
				update = update.Where(`"url" = ?`, repositoryOf(change.repository))
			} else {
				update = update.Where(`"commit_hash" = ?`, change.hash).
					Where(`"repository_id" IN (SELECT "id" FROM "patch_repository" WHERE "url" = ?)`,
						repositoryOf(change.repository))
			}
			if _, err := update.Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		repositories, _, err := patchbranch.Progress(ctx, db.DB, outward.Excluded{})
		if err != nil {
			t.Fatal(err)
		}
		if len(repositories) != 2 {
			t.Fatalf("the report lists %d repositories, want 2: %+v", len(repositories), repositories)
		}
		now, next := repositories[0], repositories[1]
		if now.URL != repositoryOf("busy") || now.State != patchbranch.Working {
			t.Fatalf("first in the report is %s (%s), want the visit under way", now.URL, now.State)
		}
		if now.Step != patchbranch.LookingUp || now.VisitLooked != 1 || now.Due != 1 {
			t.Errorf("the visit under way reads %q, %d looked, %d due; want looking up, 1 of 2",
				now.Step, now.VisitLooked, now.Due)
		}
		if next.URL != repositoryOf("later") || next.Position == 0 || next.Worst != "critical" {
			t.Errorf("next is %s at %d (%q), want the critical waiting in the plan",
				next.URL, next.Position, next.Worst)
		}
	})
}
