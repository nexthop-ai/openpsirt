// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// rowsOf reads the open rows of one recorded flaw.
func (f *fixture) rowsOf(t *testing.T, identifier string) []finding.Finding {
	t.Helper()
	var rows []finding.Finding
	if err := f.db.DB.NewSelect().Model(&rows).
		Where("vulnerability_id = ?", f.issueID(t, identifier)).
		Where("closed_at IS NULL").
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s opened nothing", identifier)
	}
	return rows
}

func TestAFlawNobodyHasRatedHasNoDeadlineUntilItIsRated(t *testing.T) {
	// The clock is set from an urgency, so it starts when there is one. Counted
	// from the recording instead, a flaw rated three weeks after it was
	// written down has already spent three weeks of its window.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name,
			Summary: "The management socket accepts a request nobody authenticated.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range f.rowsOf(t, identifier) {
			if row.DueAt != nil || row.RatedAt != nil {
				t.Errorf("an unrated flaw carries a deadline %v, rated at %v", row.DueAt, row.RatedAt)
			}
		}
		// And the list says why, rather than leaving the cell blank.
		groups, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		saw := false
		for _, group := range groups {
			if group.Vulnerability == identifier {
				saw = true
				if group.NoDeadline != finding.NotRated {
					t.Errorf("an unrated flaw is listed as %q, want %q", group.NoDeadline, finding.NotRated)
				}
			}
		}
		if !saw {
			t.Errorf("%s is not in the list", identifier)
		}

		// Written down three weeks ago, and rated now.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("opened_at = ?", time.Now().UTC().AddDate(0, 0, -21)).
			Where("vulnerability_id = ?", f.issueID(t, identifier)).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		before := time.Now().UTC()
		if _, err := f.store.Assess(ctx, who, f.productID, f.issueID(t, identifier),
			"high", "Reachable from the management network."); err != nil {
			t.Fatal(err)
		}
		own := finding.DefaultOwnWindows()
		for _, row := range f.rowsOf(t, identifier) {
			if row.RatedAt == nil || row.RatedAt.Before(before.Add(-time.Second)) {
				t.Fatalf("rating it recorded the start as %v, want about %v", row.RatedAt, before)
			}
			if row.DueAt == nil || !row.DueAt.Equal(row.RatedAt.Add(own.High)) {
				t.Errorf("a flaw rated high is due %v, want %v from its rating",
					row.DueAt, own.High)
			}
		}
	})
}

func TestARecordedFlawIsHeldToTheWindowsForOurOwnProducts(t *testing.T) {
	// A critical in a component somebody else wrote has a week, because the
	// fix is a version to take. One in our own code has to be written first.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		if err := f.setting(t, "remediation.own.due.critical", "480h"); err != nil {
			t.Fatal(err)
		}
		_, identifier, err := f.store.Enter(t.Context(), who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "critical",
			Summary: "The management socket accepts a request nobody authenticated.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range f.rowsOf(t, identifier) {
			if row.RatedAt == nil || !row.RatedAt.Equal(row.OpenedAt) {
				t.Errorf("a flaw recorded with a severity was rated at %v, want its recording %v",
					row.RatedAt, row.OpenedAt)
			}
			if row.DueAt == nil || !row.DueAt.Equal(row.OpenedAt.Add(480*time.Hour)) {
				t.Errorf("a recorded critical is due %v, want twenty days from %v",
					row.DueAt, row.OpenedAt)
			}
		}
	})
}

func TestRatingAFlawAgainDoesNotRestartItsClock(t *testing.T) {
	// A rating withdrawn and made again moves the window and keeps the start.
	// Restarted, a flaw about to fall due is given a fresh window by being
	// re-rated, which is a deferral nobody had to agree to.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name,
			Summary: "The management socket accepts a request nobody authenticated.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		issue := f.issueID(t, identifier)
		first, err := f.store.Assess(ctx, who, f.productID, issue,
			"high", "Reachable from the management network.")
		if err != nil {
			t.Fatal(err)
		}
		rated := time.Now().UTC().AddDate(0, 0, -40).Truncate(time.Microsecond)
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("rated_at = ?", rated).
			Where("vulnerability_id = ?", issue).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}

		if err := f.store.Withdraw(ctx, who, first.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Assess(ctx, who, f.productID, issue,
			"critical", "Reachable from the data plane as well."); err != nil {
			t.Fatal(err)
		}
		own := finding.DefaultOwnWindows()
		for _, row := range f.rowsOf(t, identifier) {
			if row.RatedAt == nil || !row.RatedAt.Equal(rated) {
				t.Errorf("rating it again moved the start to %v, want %v", row.RatedAt, rated)
			}
			if row.DueAt == nil || !row.DueAt.Equal(rated.Add(own.Critical)) {
				t.Errorf("re-rated critical it is due %v, want %v",
					row.DueAt, rated.Add(own.Critical))
			}
		}
	})
}

func TestOnlyAFlawReportedFromOutsideCarriesADisclosureDate(t *testing.T) {
	// The disclosure date keeps pace with a reporter's publication. A flaw
	// found here has no reporter publishing, so it carries none — and nobody
	// is owed an answer, so it raises no unanswered report either.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PrivateTriage)
		record := func(told finding.Told) string {
			t.Helper()
			_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
				TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
				Summary: "The management socket accepts a request nobody authenticated.",
				Told:    told,
			})
			if err != nil {
				t.Fatal(err)
			}
			return identifier
		}
		here := record(finding.Told{FoundHere: true})
		outside := record(finding.Told{ReportedBy: "A. Researcher"})
		// Nothing said about where it came from is a report from outside.
		unsaid := record(finding.Told{})

		for _, row := range f.rowsOf(t, here) {
			if row.DiscloseAt != nil {
				t.Errorf("a flaw found here carries a disclosure date %v", row.DiscloseAt)
			}
		}
		for _, identifier := range []string{outside, unsaid} {
			for _, row := range f.rowsOf(t, identifier) {
				if row.DiscloseAt == nil {
					t.Errorf("%s, reported from outside, carries no disclosure date", identifier)
				}
			}
		}

		// Every one of them was written with a report, which is where the
		// flag lives.
		for _, identifier := range []string{here, outside, unsaid} {
			told, err := f.store.ReportFor(ctx, who, f.issueID(t, identifier))
			if err != nil {
				t.Fatal(err)
			}
			if told == nil {
				t.Fatalf("%s was recorded with no report", identifier)
			}
			if told.FoundHere != (identifier == here) {
				t.Errorf("%s reads as found here: %v", identifier, told.FoundHere)
			}
		}

		waiting, err := f.store.Unacknowledged(ctx)
		if err != nil {
			t.Fatal(err)
		}
		named := map[string]bool{}
		for _, each := range waiting {
			named[each.Identifier] = true
		}
		if named[here] {
			t.Error("a flaw found here is waiting for somebody to answer its reporter")
		}
		if !named[outside] || !named[unsaid] {
			t.Errorf("the reports from outside are not waiting for an answer: %v", named)
		}
	})
}

func TestAnIssueSaysWhereItIsAFlawRecordedHere(t *testing.T) {
	// The issue screen opens the advisory panel on a flaw recorded here and
	// leaves it folded on a scanner's issue, which the naming refuses.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		scanned := f.anIssueHere(t, who, "A known issue in a component somebody else wrote.")
		_, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "The management socket accepts a request nobody authenticated.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		for issue, want := range map[int64]bool{scanned: false, f.issueID(t, identifier): true} {
			rows, _, err := f.store.Everywhere(ctx, who, issue, 50)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 {
				t.Fatalf("issue %d sits nowhere", issue)
			}
			for _, row := range rows {
				if row.Recorded != want {
					t.Errorf("issue %d reads as recorded here: %v, want %v", issue, row.Recorded, want)
				}
			}
		}
	})
}

func TestABuildAddedToAFlawKeepsTheClockItAlreadyHas(t *testing.T) {
	// A build added after the flaw was rated is on the clock the flaw already
	// runs. Stamped as rated on its own, the next recount gave it a whole new
	// window, which is the fresh start a re-rating is refused.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		rows, identifier, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: libnl.Name, Severity: "high",
			Summary: "The parser accepts a message it should refuse.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		rated := time.Now().UTC().AddDate(0, 0, -40).Truncate(time.Microsecond)
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("rated_at = ?", rated).
			Where("vulnerability_id = ?", rows[0].VulnerabilityID).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Affects(ctx, who, f.productID, rows[0].VulnerabilityID,
			[]int64{f.target, other}, ""); err != nil {
			t.Fatal(err)
		}
		// Any policy save recounts every recorded flaw.
		if _, err := f.store.Recompute(ctx, finding.DefaultWindows()); err != nil {
			t.Fatal(err)
		}
		want := rated.Add(finding.DefaultOwnWindows().High)
		for _, row := range f.rowsOf(t, identifier) {
			if row.RatedAt == nil || !row.RatedAt.Equal(rated) || row.DueAt == nil || !row.DueAt.Equal(want) {
				t.Errorf("the build at %d is rated %v and due %v, want %v and %v",
					row.TargetID, row.RatedAt, row.DueAt, rated, want)
			}
		}
	})
}
