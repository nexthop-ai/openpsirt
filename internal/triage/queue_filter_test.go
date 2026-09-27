// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// queued is how many claims the queue holds for the reviewer under a filter.
func (f *fixture) queued(t *testing.T, filter triage.QueueFilter) int {
	t.Helper()
	waiting, total, err := f.store.QueueNarrowed(t.Context(), f.reviewer, filter, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(waiting) != total {
		t.Fatalf("a page of %d under a total of %d", len(waiting), total)
	}
	return total
}

// claimsAbout proposes a claim about one issue at the fixture's place, as
// somebody, with an outcome.
func (f *fixture) claimsAbout(t *testing.T, issue int64, by int64, as triage.Outcome) {
	t.Helper()
	at := f.at()
	at.VulnerabilityID = issue
	who := f.triager
	if by != f.proposer {
		who = f.privateTriager(t, "second", "Second")
	}
	p := triage.Proposal{
		Place: at, Outcome: as, Reasoning: "Not reachable from anything we ship.",
		By: who.ID, NeedsApproval: true,
	}
	if as == triage.NotApplicable {
		p.Justification = triage.CodeNotInExecutePath
	}
	if _, err := f.store.Propose(t.Context(), who, p); err != nil {
		t.Fatal(err)
	}
}

func TestTheQueueNarrowsByWhoProposedAClaim(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.claimsAbout(t, f.issue, f.proposer, triage.NotApplicable)
		second := f.privateTriager(t, "second", "Second")
		f.claimsAbout(t, f.secondIssue(t), second.ID, triage.NotApplicable)

		if got := f.queued(t, triage.QueueFilter{ProposedBy: []int64{f.proposer}}); got != 1 {
			t.Errorf("%d claims by one proposer, want 1", got)
		}
		// A name that resolved to nobody narrows to nothing rather than
		// being dropped, which would answer with the whole queue.
		if got := f.queued(t, triage.QueueFilter{ProposedBy: []int64{}}); got != 0 {
			t.Errorf("a proposer nobody is left %d claims", got)
		}
		if got := f.queued(t, triage.QueueFilter{}); got != 2 {
			t.Errorf("%d claims unfiltered, want 2", got)
		}
	})
}

func TestTheQueueNarrowsByOutcome(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.claimsAbout(t, f.issue, f.proposer, triage.NotApplicable)
		f.claimsAbout(t, f.secondIssue(t), f.proposer, triage.WontFix)

		if got := f.queued(t, triage.QueueFilter{
			Outcomes: []triage.Outcome{triage.WontFix},
		}); got != 1 {
			t.Errorf("%d claims setting an issue aside, want 1", got)
		}
		if got := f.queued(t, triage.QueueFilter{
			Outcomes: []triage.Outcome{triage.WontFix, triage.NotApplicable},
		}); got != 2 {
			t.Errorf("%d claims of either outcome, want 2", got)
		}
	})
}

func TestTheQueueNarrowsBySeverityInForceInTheClaimsProduct(t *testing.T) {
	// The rating in force is what the finding is judged by everywhere else,
	// so an issue this product rated down is not severe here whatever was
	// published.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.db.DB.NewUpdate().Model((*finding.Vulnerability)(nil)).
			Set("severity = ?", "critical").Where("id = ?", f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.claimsAbout(t, f.issue, f.proposer, triage.NotApplicable)
		f.claimsAbout(t, f.secondIssue(t), f.proposer, triage.NotApplicable)

		high := triage.QueueFilter{Severities: finding.AtLeast("high")}
		if got := f.queued(t, high); got != 1 {
			t.Errorf("%d claims cover something high or worse, want the critical one", got)
		}

		rated := &finding.IssueRating{
			VulnerabilityID: f.issue, ProductID: f.product, Severity: "medium",
		}
		if _, err := f.db.DB.NewInsert().Model(rated).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if got := f.queued(t, high); got != 0 {
			t.Errorf("an issue this product rated medium still counts as high: %d", got)
		}
	})
}

func TestTheQueueNarrowsByHowOldAClaimIs(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.claimsAbout(t, f.issue, f.proposer, triage.NotApplicable)
		f.claimsAbout(t, f.secondIssue(t), f.proposer, triage.NotApplicable)
		if _, err := f.db.DB.NewUpdate().Model((*triage.Decision)(nil)).
			Set("proposed_at = ?", time.Now().UTC().AddDate(0, 0, -20)).
			Where("vulnerability_id = ?", f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		before := time.Now().UTC().AddDate(0, 0, -10)
		if got := f.queued(t, triage.QueueFilter{ProposedBefore: &before}); got != 1 {
			t.Errorf("%d claims older than ten days, want the one made twenty ago", got)
		}
	})
}

func TestTheQueueNarrowsByTheReleaseAClaimCovers(t *testing.T) {
	// A decision names no release; it covers the builds whose findings it
	// matches. So a claim with nothing open under it in a release is not
	// about that release, however it was made.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.selection(t)
		if _, _, err := f.store.Together(ctx, f.triager, in, f.wontFix(),
			triage.DefaultTogetherCap); err != nil {
			t.Fatal(err)
		}
		f.claimsAbout(t, f.secondIssue(t), f.proposer, triage.NotApplicable)

		if got := f.queued(t, triage.QueueFilter{Release: "2026.03"}); got != 1 {
			t.Errorf("%d claims cover the release, want the one made on it", got)
		}
		if got := f.queued(t, triage.QueueFilter{Release: " 2026.03 "}); got != 1 {
			t.Errorf("a release name typed with spaces matched %d claims, want 1", got)
		}
		if got := f.queued(t, triage.QueueFilter{Release: "2026.04"}); got != 0 {
			t.Errorf("%d claims cover a release that holds nothing", got)
		}
	})
}
