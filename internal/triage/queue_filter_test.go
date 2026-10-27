// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// queued is how many decisions the queue holds for the reviewer under a filter.
func (f *fixture) queued(t *testing.T, filter triage.QueueFilter) int {
	t.Helper()
	waiting, total, err := f.store.Queue(t.Context(), f.reviewer, filter, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(waiting) != total {
		t.Fatalf("a page of %d under a total of %d", len(waiting), total)
	}
	return total
}

// decisionsAbout proposes a decision about one issue at the fixture's occurrence, as
// somebody, with an outcome.
func (f *fixture) decisionsAbout(t *testing.T, issue int64, by int64, as triage.Outcome) {
	t.Helper()
	at := f.at()
	at.VulnerabilityID = issue
	who := f.triager
	if by != f.proposer {
		who = f.privateTriager(t, "second", "Second")
	}
	p := triage.Proposal{
		Occurrence: at, Outcome: as, Reasoning: "Not reachable from anything we ship.",
		By: who.ID, NeedsApproval: true,
	}
	if as == triage.NotApplicable {
		p.Justification = triage.CodeNotInExecutePath
	}
	if _, err := f.store.Propose(t.Context(), who, p); err != nil {
		t.Fatal(err)
	}
}

func TestTheQueueNarrowsByWhoProposedADecision(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.decisionsAbout(t, f.issue, f.proposer, triage.NotApplicable)
		second := f.privateTriager(t, "second", "Second")
		f.decisionsAbout(t, f.secondIssue(t), second.ID, triage.NotApplicable)

		if got := f.queued(t, triage.QueueFilter{ProposedBy: []int64{f.proposer}}); got != 1 {
			t.Errorf("%d decisions by one proposer, want 1", got)
		}
		// A name that resolved to nobody narrows to nothing rather than
		// being dropped, which would answer with the whole queue.
		if got := f.queued(t, triage.QueueFilter{ProposedBy: []int64{}}); got != 0 {
			t.Errorf("a proposer nobody is left %d decisions", got)
		}
		if got := f.queued(t, triage.QueueFilter{}); got != 2 {
			t.Errorf("%d decisions unfiltered, want 2", got)
		}
	})
}

func TestTheQueueNarrowsByOutcome(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.decisionsAbout(t, f.issue, f.proposer, triage.NotApplicable)
		f.decisionsAbout(t, f.secondIssue(t), f.proposer, triage.WontFix)

		if got := f.queued(t, triage.QueueFilter{
			Outcomes: []triage.Outcome{triage.WontFix},
		}); got != 1 {
			t.Errorf("%d decisions setting an issue aside, want 1", got)
		}
		if got := f.queued(t, triage.QueueFilter{
			Outcomes: []triage.Outcome{triage.WontFix, triage.NotApplicable},
		}); got != 2 {
			t.Errorf("%d decisions of either outcome, want 2", got)
		}
	})
}

func TestTheQueueNarrowsBySeverityInForceInTheDecisionsProduct(t *testing.T) {
	// The rating in force is what the finding is judged by everywhere else,
	// so an issue this product rated down is not severe here whatever was
	// published.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.db.DB.NewUpdate().Model((*finding.Vulnerability)(nil)).
			Set(`"severity" = ?`, "critical").Where(`"id" = ?`, f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.decisionsAbout(t, f.issue, f.proposer, triage.NotApplicable)
		f.decisionsAbout(t, f.secondIssue(t), f.proposer, triage.NotApplicable)

		high := triage.QueueFilter{Severities: finding.AtLeast("high")}
		if got := f.queued(t, high); got != 1 {
			t.Errorf("%d decisions cover something high or worse, want the critical one", got)
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

func TestTheQueueNarrowsByHowOldADecisionIs(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.decisionsAbout(t, f.issue, f.proposer, triage.NotApplicable)
		f.decisionsAbout(t, f.secondIssue(t), f.proposer, triage.NotApplicable)
		if _, err := f.db.DB.NewUpdate().Model((*triage.DecisionOccurrence)(nil)).
			Set(`"proposed_at" = ?`, time.Now().UTC().AddDate(0, 0, -20)).
			Where(`"vulnerability_id" = ?`, f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		before := time.Now().UTC().AddDate(0, 0, -10)
		if got := f.queued(t, triage.QueueFilter{ProposedBefore: &before}); got != 1 {
			t.Errorf("%d decisions older than ten days, want the one made twenty ago", got)
		}
	})
}

func TestTheQueueNarrowsByTheBranchOrTagADecisionCovers(t *testing.T) {
	// A decision names no release; it covers the builds whose findings it
	// matches. So a decision with nothing open under it in a release is not
	// about that release, however it was made.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.selection(t)
		if _, _, _, err := f.store.BulkDecision(ctx, f.triager, in, f.wontFix(),
			triage.DefaultBounds()); err != nil {
			t.Fatal(err)
		}
		f.decisionsAbout(t, f.secondIssue(t), f.proposer, triage.NotApplicable)

		if got := f.queued(t, triage.QueueFilter{BranchOrTag: "2026.03"}); got != 1 {
			t.Errorf("%d decisions cover the release, want the one made on it", got)
		}
		if got := f.queued(t, triage.QueueFilter{BranchOrTag: " 2026.03 "}); got != 1 {
			t.Errorf("a release name typed with spaces matched %d decisions, want 1", got)
		}
		if got := f.queued(t, triage.QueueFilter{BranchOrTag: "2026.04"}); got != 0 {
			t.Errorf("%d decisions cover a release that holds nothing", got)
		}
	})
}

func TestTheBranchOrTagFilterReadsOnlyFindingsTheApproverMaySee(t *testing.T) {
	// A decision that covers an undisclosed finding in a release says nothing
	// about that release to an approver who reads disclosed work alone: the
	// filter would otherwise tell them the release holds something.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.selection(t)
		if _, _, _, err := f.store.BulkDecision(ctx, f.triager, in, f.wontFix(),
			triage.DefaultBounds()); err != nil {
			t.Fatal(err)
		}
		later := f.build(t, f.product, "2026.04")
		f.finds(t, later, in.ComponentID, "place-of-libfoo", access.Private)

		public := f.holding(t, "public-approver",
			map[int64][]access.Role{f.product: {access.PublicTriage}})
		both := f.privateTriager(t, "both-approver", "Both")
		asked := func(who access.Subject, release string) int {
			_, total, err := f.store.Queue(ctx, who,
				triage.QueueFilter{BranchOrTag: release}, 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			return total
		}
		if got := asked(both, "2026.04"); got != 1 {
			t.Fatalf("somebody who reads undisclosed work sees %d decisions on the release, "+
				"so this fixture does not reach it", got)
		}
		if got := asked(public, "2026.04"); got != 0 {
			t.Errorf("an approver who reads disclosed work alone learned the release holds "+
				"%d decisions through an undisclosed finding", got)
		}
		if got := asked(public, "2026.03"); got != 1 {
			t.Errorf("the disclosed release reads %d decisions, want 1", got)
		}
	})
}
