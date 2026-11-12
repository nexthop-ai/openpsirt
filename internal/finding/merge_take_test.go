// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// filedRow is one issue row by the name it is filed under: its own
// identifier, the issue it is read as, and the value it was last taken with.
type filedRow struct {
	ID      int64   `bun:"id"`
	IssueID int64   `bun:"issue_id"`
	TakenBy *string `bun:"taken_by"`
}

// filedAs reads the row filed under a name.
func (f *fixture) filedAs(t *testing.T, name string) filedRow {
	t.Helper()
	var row filedRow
	if err := f.db.DB.NewSelect().Table("vulnerability").Column("id", "issue_id", "taken_by").
		Where(`"identifier_folded" = ?`, finding.FoldIdentifier(name)).
		Scan(t.Context(), &row); err != nil {
		t.Fatalf("read the row filed under %s: %v", name, err)
	}
	return row
}

// internAlone records each name as an issue of its own.
func (f *fixture) internAlone(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(),
			[]finding.Named{{Identifier: name}}); err != nil {
			t.Fatalf("record %s: %v", name, err)
		}
	}
}

// mergeWithin interns one report naming several issues inside a transaction
// on this handle, as a scan's apply does.
func mergeWithin(ctx context.Context, db bun.IDB, named finding.Named) error {
	return database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		_, err := finding.NewVulnerabilities(tx).Intern(ctx, []finding.Named{named})
		return err
	})
}

// A take writing the value a row already holds is skipped on MySQL and
// MariaDB, and a cluster never certifies it, so two merges of one issue on two
// nodes would both commit.
func TestEveryMergeTakesTheIssuesItNamesWithAFreshValue(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.internAlone(t, "CVE-2026-8101", "GHSA-aaaa-8101-0001", "GHSA-aaaa-8101-0002")
		var seen []string
		for _, alias := range []string{"GHSA-aaaa-8101-0001", "GHSA-aaaa-8101-0002"} {
			if err := mergeWithin(t.Context(), f.db.DB, finding.Named{
				Identifier: "CVE-2026-8101", Aliases: []string{alias}}); err != nil {
				t.Fatalf("merge %s: %v", alias, err)
			}
			by := f.filedAs(t, "CVE-2026-8101").TakenBy
			if by == nil {
				t.Fatalf("the merge of %s took the issue kept with no value", alias)
			}
			seen = append(seen, *by)
		}
		if seen[0] == seen[1] {
			t.Errorf("two merges took the issue kept with %q both times, want a fresh value each", seen[0])
		}
	})
}

// Two scans merging overlapping issues at once, one keeping a row the other
// absorbs, leave one issue. The second waits on the first's take, finds the
// row it meant to absorb is no longer its own issue, and goes again against
// what the first committed.
func TestTwoMergesOfOneIssueAtOnceLeaveOneIssue(t *testing.T) {
	servers(t, func(t *testing.T, f *fixture) {
		first, shared, second := "CVE-2026-8201", "GHSA-aaaa-8201-0001", "CVE-2026-8202"
		f.internAlone(t, first, shared, second)
		// The first keeps its own row and absorbs the shared one; the rival
		// keeps its own and absorbs the same shared row.
		hooked, rival := dbtest.RivalAfterRead(t, f.db, "vulnerability", "vulnerability_merge", 2*time.Second,
			func() error {
				return mergeWithin(context.Background(), f.db.DB, finding.Named{
					Identifier: second, Aliases: []string{shared}})
			})
		if err := mergeWithin(t.Context(), hooked, finding.Named{
			Identifier: first, Aliases: []string{shared}}); err != nil {
			t.Fatalf("the first merge: %v", err)
		}
		if err := rival(); err != nil {
			t.Fatalf("the rival merge: %v", err)
		}
		rows := map[string]filedRow{}
		for _, name := range []string{first, shared, second} {
			rows[name] = f.filedAs(t, name)
		}
		issue := rows[first].IssueID
		for name, row := range rows {
			if row.IssueID != issue {
				t.Errorf("%s is read as issue %d and %s as %d, want one issue", name, row.IssueID, first, issue)
			}
		}
		for _, row := range rows {
			if row.ID == issue && row.IssueID != row.ID {
				t.Errorf("the issue standing, %d, is read as %d", row.ID, row.IssueID)
			}
		}
	})
}

// Two writers meeting one new issue at once both record it: the second finds
// the first's row once its insert collides, and the issue is one row.
func TestTwoWritersRecordingOneNewIssueAtOnceBothSucceed(t *testing.T) {
	servers(t, func(t *testing.T, f *fixture) {
		const name = "CVE-2026-8301"
		hooked, rival := dbtest.RivalAfterRead(t, f.db, "vulnerability", "vulnerability", 2*time.Second,
			func() error {
				return mergeWithin(context.Background(), f.db.DB, finding.Named{Identifier: name})
			})
		if err := mergeWithin(t.Context(), hooked, finding.Named{Identifier: name}); err != nil {
			t.Fatalf("the writer that lost the race: %v", err)
		}
		if err := rival(); err != nil {
			t.Fatalf("the rival: %v", err)
		}
		held, err := f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).
			Where(`"identifier_folded" = ?`, finding.FoldIdentifier(name)).Count(t.Context())
		if err != nil || held != 1 {
			t.Errorf("the issue is held by %d rows (%v), want one", held, err)
		}
	})
}
