// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// secondIssue is another vulnerability, for a decision about a different issue
// at the same occurrence.
func (f *fixture) secondIssue(t *testing.T) int64 {
	t.Helper()
	interned, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(), []finding.Named{
		{Identifier: "CVE-2026-2", Severity: "low"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return interned["CVE-2026-2"]
}

// privately is somebody who may argue about undisclosed findings as well as
// disclosed ones.
func (f *fixture) privately(t *testing.T) access.Subject {
	t.Helper()
	return f.privateTriager(t, "insider", "Insider")
}

// privateTriager is the same under a name of the caller's choosing, because a
// decision that has to be agreed to needs two of them: the person who proposed
// may never be the person who approves.
func (f *fixture) privateTriager(t *testing.T, identity, display string) access.Subject {
	t.Helper()
	ctx := t.Context()
	rights := access.NewStore(f.db.DB)
	who, err := rights.Ensure(ctx, identity, display, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []access.Role{access.PublicTriage, access.PrivateTriage} {
		if err := rights.GrantRole(ctx, who.ID, f.product, role); err != nil {
			t.Fatal(err)
		}
	}
	resolved, err := rights.Resolve(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// occurrences is a finding sitting at several consumers: the shape one decision
// covers in one action.
func (f *fixture) occurrences(names ...string) []triage.Occurrence {
	out := make([]triage.Occurrence, 0, len(names))
	for _, name := range names {
		at := f.at()
		at.OccurrenceIdentity = name
		out = append(out, at)
	}
	return out
}

// keyed is what a finding asks about: its occurrences, with the versions it holds
// at each — the fixture's defaults, so they match what decisions wrote.
func (f *fixture) keyed(names ...string) []finding.Deciding {
	out := make([]finding.Deciding, 0, len(names))
	for _, at := range f.occurrences(names...) {
		out = append(out, finding.Deciding{
			ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
			OccurrenceIdentity: at.OccurrenceIdentity,
			ComponentUpstream:  at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
		})
	}
	return out
}

// decisionsMany records one decision across several occurrences, which writes one
// decision and one row per occurrence.
func (f *fixture) decisionsMany(t *testing.T, occurrences []triage.Occurrence) []*triage.DecisionOccurrence {
	t.Helper()
	proposals := make([]triage.Proposal, 0, len(occurrences))
	for _, at := range occurrences {
		proposals = append(proposals, triage.Proposal{
			Occurrence: at, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Reasoning:     "The parser is never reached: we only call the encoder.",
			By:            f.proposer, NeedsApproval: true,
		})
	}
	recorded, err := f.store.ProposeMany(t.Context(), f.triager, proposals)
	if err != nil {
		t.Fatal(err)
	}
	return recorded
}

func TestOneActionIsOneDecisionHoweverManyOccurrencesItCovers(t *testing.T) {
	// The queue lists decisions. A finding at sixty-two occurrences is one argument
	// to read.
	each(t, func(t *testing.T, f *fixture) {
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))
		for _, one := range recorded[1:] {
			if one.DecisionID != recorded[0].DecisionID {
				t.Fatalf("one action wrote rows under decisions %d and %d", recorded[0].DecisionID, one.DecisionID)
			}
		}

		waiting, total, err := f.store.Queue(t.Context(), f.reviewer, triage.QueueFilter{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(waiting) != 1 {
			t.Fatalf("%d waiting (total %d), want one decision", len(waiting), total)
		}
		if waiting[0].Rows != 3 || waiting[0].Occurrences != 3 || waiting[0].Issues != 1 {
			t.Errorf("the decision reads as %d rows, %d occurrences, %d issues; want 3, 3, 1",
				waiting[0].Rows, waiting[0].Occurrences, waiting[0].Issues)
		}
		if waiting[0].Decision.Kind != triage.FindingDecision {
			t.Errorf("a decision about a finding reads as a %q decision", waiting[0].Decision.Kind)
		}
	})
}

// The limit on one action is the one the deployment holds when the rows are
// written, read by the write itself rather than handed to it.
func TestOneActionIsHeldToTheLimitTheDeploymentHasSet(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, _, err := setting.NewStore(f.db.DB).Change(ctx, setting.BulkDecisionCap, "2"); err != nil {
			t.Fatal(err)
		}
		proposals := make([]triage.Proposal, 0, 3)
		for _, at := range f.occurrences("under-a", "under-b", "under-c") {
			proposals = append(proposals, triage.Proposal{
				Occurrence: at, Outcome: triage.NotApplicable,
				Justification: triage.CodeNotInExecutePath,
				Reasoning:     "The parser is never reached: we only call the encoder.",
				By:            f.proposer, NeedsApproval: true,
			})
		}
		if _, err := f.store.ProposeMany(ctx, f.triager, proposals); err == nil ||
			!strings.Contains(err.Error(), "the limit here is 2") {
			t.Errorf("three findings under a limit of two answered %v", err)
		}
		recorded, err := f.store.ProposeMany(ctx, f.triager, proposals[:2])
		if err != nil {
			t.Fatalf("two findings under a limit of two were refused: %v", err)
		}
		if _, err := f.store.ApproveDecision(ctx, f.reviewer, recorded[0].DecisionID, "", nil, ""); err != nil {
			t.Fatal(err)
		}
		if _, _, err := setting.NewStore(f.db.DB).Change(ctx, setting.BulkDecisionCap, "1"); err != nil {
			t.Fatal(err)
		}
		second := f.secondIssue(t)
		extending := make([]triage.Proposal, 0, 2)
		for _, p := range proposals[:2] {
			p.Occurrence.VulnerabilityID = second
			extending = append(extending, p)
		}
		if _, err := f.store.Extend(ctx, f.triager, recorded[0].DecisionID,
			extending); err == nil || !strings.Contains(err.Error(), "the limit here is 1") {
			t.Errorf("an extension over the limit answered %v", err)
		}
	})
}

func TestApprovingADecisionApprovesEveryRowInIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b"))

		done, err := f.store.ApproveDecision(ctx, f.reviewer, recorded[0].DecisionID, "", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		if done.Approved != 2 || done.Returned != nil {
			t.Errorf("approving the decision agreed to %d rows and returned %v", done.Approved, done.Returned)
		}
		for _, at := range f.occurrences("under-a", "under-b") {
			if standing, _ := f.store.Applying(ctx, at); standing == nil || standing.State != triage.Approved {
				t.Errorf("after approving the decision, nothing approved stands at %s", at.OccurrenceIdentity)
			}
		}
		if _, total, _ := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0); total != 0 {
			t.Errorf("an approved decision is still waiting: %d in the queue", total)
		}
	})
}

func TestTheProposerMayNotApproveTheirOwnDecision(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		recorded := f.decisionsMany(t, f.occurrences("under-a"))
		_, err := f.store.ApproveDecision(t.Context(), f.triager, recorded[0].DecisionID, "", nil, "")
		if !errors.Is(err, triage.ErrSamePerson) {
			t.Errorf("the proposer approving their own decision answered %v", err)
		}
	})
}

func TestRowsSetAsideReturnAsTheirOwnDecision(t *testing.T) {
	// An approver of a bulk decision who found the handful that do not fit
	// should not have to choose between refusing everything and agreeing to
	// everything: the rest is approved, and those go back with the reason
	// .
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))
		aside := recorded[2]

		done, err := f.store.ApproveDecision(ctx, f.reviewer, recorded[0].DecisionID, "",
			[]int64{aside.ID}, "This one is reachable from the CLI.")
		if err != nil {
			t.Fatal(err)
		}
		if done.Approved != 2 {
			t.Errorf("approved %d rows, want the 2 not set aside", done.Approved)
		}
		if done.Returned == nil || done.Returned.Kind != triage.ReturnedDecision ||
			done.Returned.DerivedFrom == nil || *done.Returned.DerivedFrom != recorded[0].DecisionID {
			t.Fatalf("the rows set aside did not return as a decision derived from the original: %+v", done.Returned)
		}
		if done.Returned.ProposedBy != f.proposer {
			t.Errorf("the returned decision belongs to %d, not to the proposer %d", done.Returned.ProposedBy, f.proposer)
		}

		moved, _, err := f.store.Read(ctx, f.reviewer, aside.ID)
		if err != nil {
			t.Fatal(err)
		}
		if moved.DecisionID != done.Returned.ID {
			t.Errorf("the row set aside still belongs to decision %d", moved.DecisionID)
		}
		if moved.State != triage.Proposed || moved.SentBackAt == nil {
			t.Errorf("the row set aside reads as %s and sent back at %v", moved.State, moved.SentBackAt)
		}
		said, err := f.store.Discussion(ctx, f.reviewer, moved.DecisionID)
		if err != nil || len(said) != 1 || said[0].Body != "This one is reachable from the CLI." {
			t.Errorf("the reason did not travel as a comment: %v %v", said, err)
		}
		// Sent back, so not waiting on an approver; and the approved rest is
		// not waiting either.
		if _, total, _ := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0); total != 0 {
			t.Errorf("%d decisions still waiting after approving with rows set aside", total)
		}
	})
}

func TestSettingRowsAsideNeedsAReason(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b"))
		_, err := f.store.ApproveDecision(t.Context(), f.reviewer, recorded[0].DecisionID, "",
			[]int64{recorded[1].ID}, "")
		if err == nil || !strings.Contains(err.Error(), "set aside") {
			t.Errorf("rows were set aside with nothing said about why: %v", err)
		}
		_, err = f.store.ApproveDecision(t.Context(), f.reviewer, recorded[0].DecisionID, "",
			[]int64{999999}, "Not one of ours.")
		if err == nil {
			t.Error("a row that is not part of the decision was accepted as set aside")
		}
	})
}

func TestSendingADecisionBackTakesEveryRowOutOfTheQueue(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b"))
		back, err := f.store.SendBackDecision(ctx, f.reviewer, recorded[0].DecisionID,
			"Say which config file.")
		if err != nil {
			t.Fatal(err)
		}
		if back.Sent != 2 || back.Author != f.proposer {
			t.Errorf("sent %d rows back to %d; want 2 to %d", back.Sent, back.Author, f.proposer)
		}
		if back.DecisionOccurrence.ID != recorded[0].ID {
			t.Errorf("the representative row is %d; want the earliest, %d", back.DecisionOccurrence.ID, recorded[0].ID)
		}
		if _, total, _ := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0); total != 0 {
			t.Errorf("a decision sent back is still waiting: %d", total)
		}
	})
}

func TestAnExtensionCarriesOnlyAnApprovedDecisionToTheSameOccurrences(t *testing.T) {
	// The nightly case: a new issue in a component under a consumer that
	// already carries an agreed decision with the same justification.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		source := f.decisionsMany(t, f.occurrences("under-a", "under-b"))

		another := f.at()
		another.VulnerabilityID = f.secondIssue(t)
		another.OccurrenceIdentity = "under-a"
		extension := triage.Proposal{
			Occurrence: another, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Reasoning:     "Same code path as the last one; still never reached.",
			By:            f.proposer, NeedsApproval: true,
		}

		// Not while the source is only proposed.
		if _, err := f.store.Extend(ctx, f.triager, source[0].DecisionID,
			[]triage.Proposal{extension}); !errors.Is(err, triage.ErrNotExtendable) {
			t.Errorf("a decision nobody agreed to was carried: %v", err)
		}
		if _, err := f.store.ApproveDecision(ctx, f.reviewer, source[0].DecisionID, "", nil, ""); err != nil {
			t.Fatal(err)
		}

		// Not to a different occurrence.
		elsewhere := extension
		elsewhere.Occurrence.OccurrenceIdentity = "under-z"
		if _, err := f.store.Extend(ctx, f.triager, source[0].DecisionID,
			[]triage.Proposal{elsewhere}); !errors.Is(err, triage.ErrNotExtendable) {
			t.Errorf("a decision was carried to an occurrence it does not sit at: %v", err)
		}
		// Not with a different justification.
		differently := extension
		differently.Justification = triage.ComponentNotPresent
		if _, err := f.store.Extend(ctx, f.triager, source[0].DecisionID,
			[]triage.Proposal{differently}); !errors.Is(err, triage.ErrNotExtendable) {
			t.Errorf("a decision was carried with a different justification: %v", err)
		}
		// Not to the issue it already covers.
		same := extension
		same.Occurrence.VulnerabilityID = f.issue
		if _, err := f.store.Extend(ctx, f.triager, source[0].DecisionID,
			[]triage.Proposal{same}); !errors.Is(err, triage.ErrNotExtendable) {
			t.Errorf("a decision was carried to the issue it already covers: %v", err)
		}

		recorded, err := f.store.Extend(ctx, f.triager, source[0].DecisionID, []triage.Proposal{extension})
		if err != nil {
			t.Fatal(err)
		}
		waiting, _, err := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 1 || waiting[0].Decision.ID != recorded[0].DecisionID {
			t.Fatalf("the extension is not what is waiting: %+v", waiting)
		}
		if waiting[0].Decision.Kind != triage.ExtensionDecision ||
			waiting[0].Decision.DerivedFrom == nil || *waiting[0].Decision.DerivedFrom != source[0].DecisionID {
			t.Errorf("the extension does not say what it carries: %+v", waiting[0].Decision)
		}
		// And it still needs a second person: nothing stands at the new issue
		// until somebody agrees.
		if standing, _ := f.store.Applying(ctx, another); standing != nil {
			t.Error("an extension suppressed the new issue before anybody agreed")
		}
	})
}

func TestAFindingReportsWhatStandsWhatStoodAndWhatMightCarry(t *testing.T) {
	// The questions somebody returning to a finding asks: what stands here,
	// what was argued before, and whether an argument already agreed to
	// reaches this .
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		occurrences := []string{"under-a", "under-b"}

		// Nothing yet.
		standing, err := f.store.StandingAt(ctx, f.reviewer, f.product, f.issue, f.keyed(occurrences...))
		if err != nil || len(standing) != 0 {
			t.Fatalf("an undecided finding reports %d standing decisions (%v)", len(standing), err)
		}

		first := f.decisionsMany(t, f.occurrences(occurrences...))
		standing, err = f.store.StandingAt(ctx, f.reviewer, f.product, f.issue, f.keyed(occurrences...))
		if err != nil || len(standing) != 1 {
			t.Fatalf("a proposed decision is not reported as standing: %d (%v)", len(standing), err)
		}
		if standing[0].Occurrences != 2 || standing[0].DecisionOccurrence.State != triage.Proposed || standing[0].ApprovedAt != nil {
			t.Errorf("a proposed decision reads as %+v", standing[0])
		}
		if _, err := f.store.ApproveDecision(ctx, f.reviewer, first[0].DecisionID, "", nil, ""); err != nil {
			t.Fatal(err)
		}
		standing, _ = f.store.StandingAt(ctx, f.reviewer, f.product, f.issue, f.keyed(occurrences...))
		if len(standing) != 1 || standing[0].ApprovedBy != f.approver || standing[0].ApprovedAt == nil {
			t.Errorf("an approved decision does not say who agreed: %+v", standing)
		}

		// Withdrawn, it is history with a date — and offered back. Withdrawing
		// takes the whole argument back, so every row of the decision is history:
		// holding part of one back is setting rows aside, which is a different
		// act with a different record.
		if _, err := f.store.Withdraw(ctx, f.triager, first[0].DecisionID); err != nil {
			t.Fatal(err)
		}
		earlier, err := f.store.EarlierAt(ctx, f.reviewer, f.product, f.issue, occurrences)
		if err != nil || len(earlier) != len(first) {
			t.Fatalf("a withdrawn decision is not offered back: %d (%v)", len(earlier), err)
		}
		if earlier[0].DecisionOccurrence.State != triage.Withdrawn || earlier[0].DecisionOccurrence.EndedAt == nil {
			t.Errorf("a withdrawn decision occurrence does not say when: %+v", earlier[0].DecisionOccurrence)
		}
		if earlier[0].Reasoning == "" || earlier[0].ApprovedBy != f.approver {
			t.Errorf("what was argued, and who agreed, did not come back: %+v", earlier[0])
		}

		// An approved decision about another issue at the same occurrence may carry.
		other := f.at()
		other.VulnerabilityID = f.secondIssue(t)
		other.OccurrenceIdentity = "under-b"
		agreed := f.decisionsMany(t, []triage.Occurrence{other})
		if _, err := f.store.ApproveDecision(ctx, f.reviewer, agreed[0].DecisionID, "", nil, ""); err != nil {
			t.Fatal(err)
		}
		similar, err := f.store.SimilarAt(ctx, f.reviewer, f.product, f.issue, occurrences)
		if err != nil || len(similar) != 1 || similar[0].Decision.ID != agreed[0].DecisionID {
			t.Fatalf("the approved decision about the other issue is not offered: %+v (%v)", similar, err)
		}
		if similar[0].Issues != 1 || similar[0].ApprovedBy != f.approver || similar[0].Reasoning == "" {
			t.Errorf("what may carry is missing its size, its approver or its words: %+v", similar[0])
		}
	})
}

func TestADecisionIsShownOnlyToSomebodyWhoMayActOnAllOfIt(t *testing.T) {
	// Acting on a decision is acting on the argument, which does not come in
	// halves. A decision spanning a disclosed and an undisclosed finding is not
	// shown to somebody who may agree to only the disclosed half.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		open := f.at()
		open.OccurrenceIdentity = "under-a"
		hidden := f.at()
		hidden.OccurrenceIdentity = "under-b"
		hidden.Visibility = access.Private

		insider := f.privately(t)
		proposals := []triage.Proposal{}
		for _, at := range []triage.Occurrence{open, hidden} {
			proposals = append(proposals, triage.Proposal{
				Occurrence: at, Outcome: triage.WontFix,
				Reasoning: "Not worth the change.", By: insider.ID, NeedsApproval: true,
			})
		}
		if _, err := f.store.ProposeMany(ctx, insider, proposals); err != nil {
			t.Fatal(err)
		}

		// The public reviewer may agree to one row and not the other, so the
		// decision is not theirs to act on.
		if _, total, err := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0); err != nil || total != 0 {
			t.Errorf("a decision half of which is undisclosed was shown to a public reviewer: %d (%v)", total, err)
		}
		// The person who proposed it is not shown it either, and for a
		// different reason: approving your own is refused, so a queue holding
		// it would be a list of work they cannot do.
		if _, total, err := f.store.Queue(ctx, insider, triage.QueueFilter{}, 50, 0); err != nil || total != 0 {
			t.Errorf("somebody was shown their own decision in the queue: %d (%v)", total, err)
		}
		// They find it by asking for their own, which is the other question:
		// what did I propose that nobody has agreed to. Without this the two
		// assertions above would pass on a queue that shows nothing to
		// anybody.
		if _, total, err := f.store.Queue(ctx, insider, triage.QueueFilter{Mine: true}, 50, 0); err != nil || total != 1 {
			t.Errorf("a decision's proposer could not find it among their own: %d (%v)", total, err)
		}
	})
}

// counting is a query hook that counts statements, so a test can pin that an
// action is a bounded number of them however many rows it touches.
type counting struct{ n int }

func (c *counting) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	c.n++
	return ctx
}
func (c *counting) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestApprovingADecisionIsABoundedNumberOfStatementsHoweverLargeItIs(t *testing.T) {
	// A decision over a kernel is two thousand rows. Approved one row at a time
	// that is a count and a conditional update per row, which was measured at
	// 15.6 s for 1,760 rows on the demo; approved as a set it is a handful
	// of statements whatever the size. The invariant pinned here is the
	// statement count, which is what a per-row loop cannot satisfy.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		names := make([]string, 0, 500)
		for i := 0; i < 500; i++ {
			names = append(names, fmt.Sprintf("under-%03d", i))
		}
		recorded := f.decisionsMany(t, f.occurrences(names...))

		hook := &counting{}
		f.hook(hook)
		started := time.Now()
		done, err := f.store.ApproveDecision(ctx, f.reviewer, recorded[0].DecisionID, "batch",
			[]int64{recorded[0].ID, recorded[1].ID}, "These two are reachable.")
		elapsed := time.Since(started)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("approving 500 rows with two set aside: %d statements in %s", hook.n, elapsed)
		if done.Approved != 498 || done.Returned == nil {
			t.Fatalf("approved %d and returned %v", done.Approved, done.Returned)
		}
		// Generous, and independent of the row count: a per-row loop is at
		// least a thousand here.
		if hook.n > 24 {
			t.Errorf("approving a 500-row decision took %d statements; the work has to be set-based", hook.n)
		}
		// Every row that was meant to be approved is, with its approval
		// naming the revision it stands on and what it covered.
		var approvals []triage.Approval
		if err := f.db.DB.NewSelect().Model(&approvals).Where(`"batch" = ?`, "batch").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		// One approval, because one act is one argument: an approver reads
		// the words once and agrees to them once. Per row it was 498 copies
		// of one agreement, each able to go on standing after the words
		// changed.
		if len(approvals) != 1 {
			t.Errorf("%d approvals recorded, want the one the approver gave", len(approvals))
		}
		for _, a := range approvals {
			if a.Covered == nil || a.RevisionID == 0 {
				t.Fatalf("an approval was recorded without what it covered or which words: %+v", a)
			}
		}
	})
}

func TestAStandingDecisionReportsHowItsRowsStandNotOneRowsState(t *testing.T) {
	// One row approved beside forty-three set aside read as "approved",
	// because the representative row's state stood in for the decision's.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		occurrences := []string{"under-a", "under-b", "under-c"}
		recorded := f.decisionsMany(t, f.occurrences(occurrences...))

		// An approver agrees to two and sets the third aside, which is the one
		// act that leaves a decision's rows in two states.
		agreed, err := f.store.ApproveDecision(ctx, f.reviewer, recorded[0].DecisionID, "",
			[]int64{recorded[2].ID}, "Which config file?")
		if err != nil {
			t.Fatal(err)
		}
		if agreed.Approved != 2 || agreed.Returned == nil {
			t.Fatalf("agreeing to two of three read as %+v", agreed)
		}

		standing, err := f.store.StandingAt(ctx, f.reviewer, f.product, f.issue, f.keyed(occurrences...))
		if err != nil || len(standing) != 2 {
			t.Fatalf("standing reads as %+v (%v)", standing, err)
		}
		var kept, aside triage.StandingDecision
		for _, one := range standing {
			if one.Decision.Kind == triage.ReturnedDecision {
				aside = one
			} else {
				kept = one
			}
		}
		if kept.State != triage.Approved || kept.Rows.Approved != 2 || kept.Rows.Proposed != 0 {
			t.Errorf("the agreed part reads as %s with rows %+v", kept.State, kept.Rows)
		}
		if aside.State != triage.Proposed || aside.Rows.SentBack != 1 || aside.Rows.Approved != 0 {
			t.Errorf("the part set aside reads as %s with rows %+v", aside.State, aside.Rows)
		}
		if aside.SentBackAt == nil || aside.SentBackBecause != "Which config file?" {
			t.Errorf("what the approver asked for did not come back: %v %q",
				aside.SentBackAt, aside.SentBackBecause)
		}
	})
}

func TestOneActionRecordsOneArgument(t *testing.T) {
	// The defect this closes: one act wrote one argument and a copy of it per
	// occurrence, each revisable on its own. A decision reaching forty-four occurrences
	// was forty-four copies of one sentence, and revising one returned that
	// row to the queue while the other forty-three went on saying the old
	// thing under a decision that read as agreed.
	//
	// The argument is the decision's now, and nothing underneath holds a second
	// copy of it to disagree with.
	each(t, func(t *testing.T, f *fixture) {
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))
		if len(recorded) != 3 {
			t.Fatalf("recorded %d rows, want one per occurrence", len(recorded))
		}

		var decisions []triage.Decision
		if err := f.db.DB.NewSelect().Model(&decisions).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(decisions) != 1 {
			t.Fatalf("three occurrences under one action wrote %d decisions", len(decisions))
		}
		if decisions[0].Outcome != triage.NotApplicable {
			t.Errorf("the decision says %q", decisions[0].Outcome)
		}
		if decisions[0].Justification == nil ||
			*decisions[0].Justification != string(triage.CodeNotInExecutePath) {
			t.Error("the decision does not carry the justification the act was recorded with")
		}
		// Every row points at that one argument, rather than carrying its own.
		for _, one := range recorded {
			if one.Decision == nil || one.Decision.ID != decisions[0].ID {
				t.Fatalf("a row of the action does not read back the decision it belongs to")
			}
		}
	})
}

func TestAnActionThatSaysTwoThingsIsRefused(t *testing.T) {
	// The capacity that made the copies possible: a proposal per occurrence
	// permitted a per-occurrence outcome and version, and nothing has ever produced
	// one. A set that disagrees is two decisions somebody meant to record as one,
	// and taking the first quietly loses whichever half was not first.
	//
	// Each case differs from the first proposal in one field alone, so each
	// reaches the one refusal it names.
	day := time.Now().UTC().AddDate(0, 0, 30).Truncate(24 * time.Hour)
	later := day.AddDate(0, 0, 1)
	cases := []struct {
		name   string
		said   string
		differ func(p *triage.Proposal)
	}{
		{"outcome", "one outcome", func(p *triage.Proposal) { p.Outcome, p.Justification = triage.WontFix, "" }},
		{"justification", "one justification", func(p *triage.Proposal) { p.Justification = triage.CodeNotPresent }},
		{"mitigation", "one mitigation", func(p *triage.Proposal) { p.Mitigation = "b" }},
		{"fixed version", "one fixed version", func(p *triage.Proposal) { p.FixedVersion = "1.1" }},
		{"upgrade version", "one version to upgrade to", func(p *triage.Proposal) { p.UpgradeTo = "2.1" }},
		{"date to look again", "one date to look again", func(p *triage.Proposal) { p.DeferredUntil = &later }},
		{"date to act by", "one date to act by", func(p *triage.Proposal) { p.CommittedTo = &later }},
		{"reasoning", "one piece of reasoning", func(p *triage.Proposal) { p.Reasoning = "The encoder is never reached either." }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				occurrences := f.occurrences("under-a", "under-b")
				proposals := make([]triage.Proposal, 0, len(occurrences))
				for i, at := range occurrences {
					p := triage.Proposal{
						Occurrence: at, Outcome: triage.NotApplicable,
						Justification: triage.CodeNotInExecutePath,
						Mitigation:    "a", FixedVersion: "1.0", UpgradeTo: "2.0",
						DeferredUntil: &day, CommittedTo: &day,
						Reasoning: "The parser is never reached: we only call the encoder.",
						By:        f.proposer, NeedsApproval: true,
					}
					if i == 1 {
						c.differ(&p)
					}
					proposals = append(proposals, p)
				}
				_, err := f.store.ProposeMany(t.Context(), f.triager, proposals)
				if err == nil {
					t.Fatalf("an action recording two of its %s was accepted", c.name)
				}
				if !strings.Contains(err.Error(), c.said) {
					t.Errorf("refused with %q, which does not say %q", err, c.said)
				}
				// And nothing was written: half an action is not one.
				count, err := f.db.DB.NewSelect().Model((*triage.Decision)(nil)).Count(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Errorf("a refused action left %d decisions behind", count)
				}
			})
		})
	}
}

// agreeTo is one person agreeing to a whole decision, which is what agreeing is:
// a decision is one argument, so an approver reads the words once and agrees to
// them once.
func agreeTo(ctx context.Context, store *triage.Store, who access.Subject,
	decisionID int64, batch string) error {

	_, err := store.ApproveDecision(ctx, who, decisionID, batch, nil, "")
	return err
}

func TestAProposerMayHoldPartOfTheirOwnDecisionBack(t *testing.T) {
	// The approver's side of this existed and the proposer's did not, so
	// "this holds for most of them but not those four" was unavailable to the
	// person best placed to say it: whoever wrote a bulk decision could only
	// withdraw the whole thing and start again.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))

		held, err := f.store.Split(ctx, f.triager, recorded[0].DecisionID,
			[]int64{recorded[2].ID}, "This one is reachable from the CLI.")
		if err != nil {
			t.Fatal(err)
		}
		if held.Kind != triage.ReturnedDecision || held.DerivedFrom == nil ||
			*held.DerivedFrom != recorded[0].DecisionID {
			t.Fatalf("the rows held back are not a decision derived from the original: %+v", held)
		}
		if held.ProposedBy != f.proposer {
			t.Errorf("the new decision belongs to %d, not to its author %d", held.ProposedBy, f.proposer)
		}
		// The argument travels with it: a decision with none is one nobody can be
		// asked to agree to.
		if held.Outcome != recorded[0].Decision.Outcome {
			t.Errorf("the decision held back says %q", held.Outcome)
		}
		said, err := f.store.Discussion(ctx, f.triager, held.ID)
		if err != nil || len(said) != 1 || said[0].Body != "This one is reachable from the CLI." {
			t.Errorf("the reason did not travel with the rows: %v %v", said, err)
		}

		moved, _, err := f.store.Read(ctx, f.triager, recorded[2].ID)
		if err != nil {
			t.Fatal(err)
		}
		if moved.DecisionID != held.ID || moved.SentBackAt == nil {
			t.Errorf("the row held back reads as decision %d, sent back at %v",
				moved.DecisionID, moved.SentBackAt)
		}
		// And it is out of the queue: it sits with its author until the
		// argument for it is stated again.
		waiting, _, err := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 1 || waiting[0].Rows != 2 {
			t.Errorf("the queue holds %d decisions, the first of %d rows", len(waiting),
				func() int {
					if len(waiting) == 0 {
						return 0
					}
					return waiting[0].Rows
				}())
		}
	})
}

func TestSplittingIsTheProposersActAndSettingAsideIsTheApprovers(t *testing.T) {
	// Each is refused to the other. An approver holding rows back is agreeing
	// to the rest in the same action, so a proposer doing it would be
	// approving their own decision; and an approver splitting instead would be
	// taking the author's act without agreeing to anything.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))

		if _, err := f.store.Split(ctx, f.reviewer, recorded[0].DecisionID,
			[]int64{recorded[2].ID}, "Not this one."); err == nil {
			t.Error("somebody who did not make the decision held part of it back")
		}
		if _, err := f.store.ApproveDecision(ctx, f.triager, recorded[0].DecisionID, "",
			[]int64{recorded[2].ID}, "Not this one."); !errors.Is(err, triage.ErrSamePerson) {
			t.Errorf("the proposer set rows of their own decision aside: %v", err)
		}
	})
}

func TestHoldingBackNothingOrEverythingIsRefused(t *testing.T) {
	// A stray identifier is more likely a mistake than a wish, and holding
	// back all of what is being argued is a revision or a withdrawal rather
	// than a split — two decisions saying the same thing is not what anybody
	// meant.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b"))
		decisionID := recorded[0].DecisionID

		for _, c := range []struct {
			what   string
			rows   []int64
			reason string
		}{
			{"no rows", nil, "Because."},
			{"no reason", []int64{recorded[1].ID}, "   "},
			{"a row of another decision", []int64{recorded[1].ID + 10_000}, "Because."},
			{"every row", []int64{recorded[0].ID, recorded[1].ID}, "Because."},
		} {
			if _, err := f.store.Split(ctx, f.triager, decisionID, c.rows, c.reason); err == nil {
				t.Errorf("holding back %s was accepted", c.what)
			}
		}
	})
}

func TestRecordingADecisionIsABoundedNumberOfStatementsHoweverManyOccurrencesItCovers(t *testing.T) {
	// One decision covers every occurrence it sits at, and on shared code that is
	// many: 507 for the worst case on the demo. Written one at a time that is
	// a round trip each — 1.4 s on MySQL — which is the shape the scan apply
	// already avoids, for the same reason.
	each(t, func(t *testing.T, f *fixture) {
		names := make([]string, 0, 500)
		for i := 0; i < 500; i++ {
			names = append(names, fmt.Sprintf("under-%03d", i))
		}
		occurrences := f.occurrences(names...)
		proposals := make([]triage.Proposal, 0, len(occurrences))
		for _, at := range occurrences {
			proposals = append(proposals, triage.Proposal{
				Occurrence: at, Outcome: triage.NotApplicable,
				Justification: triage.CodeNotInExecutePath,
				Reasoning:     "The parser is never reached: we only call the encoder.",
				By:            f.proposer, NeedsApproval: true,
			})
		}

		hook := &counting{}
		f.hook(hook)
		recorded, err := f.store.ProposeMany(t.Context(), f.triager, proposals)
		if err != nil {
			t.Fatal(err)
		}
		if len(recorded) != len(occurrences) {
			t.Fatalf("recorded %d rows for %d occurrences", len(recorded), len(occurrences))
		}
		t.Logf("recording 500 occurrences: %d statements", hook.n)
		// Generous, and independent of the occurrence count: a row at a time is at
		// least five hundred here.
		if hook.n > 24 {
			t.Errorf("recording a 500-occurrence decision took %d statements; the work has to be batched",
				hook.n)
		}
	})
}

// A decision that was sent back applies to nothing until it is revised, which is
// what the notice to its author says in those words.
//
// Only a decision needing nobody can be both sent back and standing — a gated
// one suppresses nothing while it waits — and that is exactly the one that
// went on hiding the finding after an approver had returned it.
func TestADecisionSentBackStopsApplying(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		soon := time.Now().UTC().Add(24 * time.Hour)
		short, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.at(), Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Not this sprint.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if short.NeedsApproval {
			t.Fatal("a short deferral was gated, so this tests nothing")
		}
		if standing, _ := f.store.Applying(ctx, f.at()); standing == nil {
			t.Fatal("a deferral needing nobody did not stand, so this tests nothing")
		}

		if _, err := f.store.SendBackDecision(ctx, f.reviewer, short.DecisionID,
			"Say which sprint, and why not this one."); err != nil {
			t.Fatal(err)
		}
		if standing, _ := f.store.Applying(ctx, f.at()); standing != nil {
			t.Error("a decision an approver sent back went on suppressing the finding")
		}

		// And revising it puts it back, which is what returning it asked for.
		if _, err := f.store.Revise(ctx, f.triager, short.DecisionID,
			"Waiting on the 6.2 rebase, which lands next sprint."); err != nil {
			t.Fatal(err)
		}
		if standing, _ := f.store.Applying(ctx, f.at()); standing == nil {
			t.Error("a revised decision did not start applying again")
		}
	})
}

// The personal page counts only the rows this person may still read.
//
// The page query narrowed and the follow-up row read did not, and a decision's
// rows need not agree about visibility — so a decision listed through one
// disclosed row counted its undisclosed ones into the row, issue and occurrence
// totals, and could hand one of them back as the decision's representative,
// carrying its issue and its occurrence. A count is the leak even where no row is
// shown, and the page's own docstring promises the opposite: losing the
// reading of something does not leave a list of its issues behind here.
func TestThePersonalPageCountsOnlyWhatIsStillReadable(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// One decision over two occurrences, one of them undisclosed.
		here, hidden := f.at(), f.at()
		hidden.OccurrenceIdentity = "undisclosed-place"
		hidden.Visibility = access.Private
		// Proposed while they could still read both, which is the only way a
		// decision comes to hold a row its proposer may not read.
		both := access.NewPerson(f.proposer, "proposer", false,
			map[int64][]access.Role{f.product: {access.PublicTriage, access.PrivateTriage}}, 0)
		if _, err := f.store.ProposeMany(ctx, both, []triage.Proposal{
			{
				Occurrence: here, Outcome: triage.WontFix,
				Reasoning: "Not worth the churn.", By: f.proposer,
			},
			{
				Occurrence: hidden, Outcome: triage.WontFix,
				Reasoning: "Not worth the churn.", By: f.proposer,
			},
		}); err != nil {
			t.Fatal(err)
		}

		// Their private reading is withdrawn; the public half stays.
		page, total, err := f.store.Became(ctx, f.triager, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(page) != 1 {
			t.Fatalf("the page holds %d of %d decisions, want the one they proposed", len(page), total)
		}
		if page[0].Rows != 1 || page[0].Occurrences != 1 {
			t.Errorf("it counts %d rows at %d occurrences, want the one they may still read",
				page[0].Rows, page[0].Occurrences)
		}
		if page[0].DecisionOccurrence.OccurrenceIdentity == hidden.OccurrenceIdentity {
			t.Error("an undisclosed occurrence was handed back as the decision's representative")
		}
	})
}

func TestAnExtensionMayNotDuplicateAnyIssueItsSourceCovers(t *testing.T) {
	// A decision covers as many issues as the action that wrote it. Asking only
	// the first row's issue admitted an extension duplicating any of the
	// others, so one issue at one occurrence ended up under two live decisions.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		another := f.at()
		another.VulnerabilityID = f.secondIssue(t)
		says := func(at triage.Occurrence) triage.Proposal {
			return triage.Proposal{
				Occurrence: at, Outcome: triage.NotApplicable,
				Justification: triage.CodeNotInExecutePath,
				Reasoning:     "The parser is never reached: we only call the encoder.",
				By:            f.proposer, NeedsApproval: true,
			}
		}
		source, err := f.store.ProposeMany(ctx, f.triager,
			[]triage.Proposal{says(f.at()), says(another)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ApproveDecision(ctx, f.reviewer, source[0].DecisionID, "", nil, ""); err != nil {
			t.Fatal(err)
		}

		// The second issue, which the source covers and its first row does not.
		if _, err := f.store.Extend(ctx, f.triager, source[0].DecisionID,
			[]triage.Proposal{says(another)}); !errors.Is(err, triage.ErrNotExtendable) {
			t.Errorf("a decision was carried to an issue it already covers: %v", err)
		}
	})
}

func TestAnUndoReportsWhatReturnedToWaitingRatherThanWhatWasConsidered(t *testing.T) {
	// A row carrying a second standing agreement is left where it is,
	// because undoing a batch is undoing that batch. Counting the candidates
	// rather than the write told the proposer their decision had come back when
	// nothing about it had moved.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		second := f.privateTriager(t, "second-approver", "Second Approver")
		claimed := f.decisions(t, f.at())
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.DecisionID, "one-afternoon"); err != nil {
			t.Fatal(err)
		}
		// The second agreement is written directly. Approving twice is
		// refused — the rows are no longer waiting — so this is the state the
		// undo's own condition is written for, and the only way to reach it.
		var given triage.Approval
		if err := f.db.DB.NewSelect().Model(&given).
			Where(`"decision_id" = ?`, claimed.DecisionID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		also := triage.Approval{
			DecisionID: given.DecisionID, RevisionID: given.RevisionID,
			ApprovedBy: second.ID, ApprovedAt: given.ApprovedAt,
			Batch: func() *string { batch := "another-afternoon"; return &batch }(),
		}
		if _, err := f.db.DB.NewInsert().Model(&also).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		undone, err := f.store.UndoBatch(ctx, f.reviewer, "one-afternoon")
		if err != nil {
			t.Fatal(err)
		}
		if undone.Rows != 0 {
			t.Errorf("an undo reports %d rows returned to waiting while another agreement still stands",
				undone.Rows)
		}
		if state := f.stateOf(t, claimed.ID); state != triage.Approved {
			t.Errorf("the row is %s while an agreement nobody took back still stands", state)
		}
	})
}

func TestRevisingYourOwnDecisionIsNotSomebodyElseUndoingIt(t *testing.T) {
	// Revising withdraws every agreement standing on the old words, which is
	// the proposer's own act. Read off the withdrawal alone it came back as
	// "undone" and named the approver, so a proposer restating their decision was
	// told somebody had taken their agreement back.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.decisions(t, f.at())
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(ctx, f.triager, claimed.DecisionID,
			"Restated: the encoder is the only caller."); err != nil {
			t.Fatal(err)
		}

		page, _, err := f.store.Became(ctx, f.triager, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(page) != 1 {
			t.Fatalf("the page holds %d decisions, want the one", len(page))
		}
		if page[0].Happened != triage.StillWaiting {
			t.Errorf("a proposer restating their own decision reads as %q, want %q",
				page[0].Happened, triage.StillWaiting)
		}
	})
}

// Holding rows back that an approval took meanwhile moves nothing it took.
//
// Both read the rows as waiting and the approval commits first. A split
// matching on the identifiers alone would move approved rows into a new decision
// and send them back to their author. The servers only, because SQLite's one
// connection cannot hold the two transactions open at once.
func TestHoldingRowsBackThatAnApprovalTookMovesNothing(t *testing.T) {
	servers(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		recorded := f.decisionsMany(t, f.occurrences("under-a", "under-b", "under-c"))
		hook := &beforeHoldingBack{run: func() {
			if err := agreeTo(context.Background(), f.store, f.reviewer,
				recorded[0].DecisionID, ""); err != nil {
				t.Errorf("agreeing: %v", err)
			}
		}}
		f.hook(hook)
		if _, err := f.store.Split(ctx, f.triager, recorded[0].DecisionID,
			[]int64{recorded[2].ID}, "This one is reachable from the CLI."); err == nil {
			t.Error("holding back a row approved meanwhile was reported as done")
		}
		if !hook.fired {
			t.Fatal("the approval never ran between the read and the write, so this tests nothing")
		}
		row, _, err := f.store.Read(ctx, f.triager, recorded[2].ID)
		if err != nil {
			t.Fatal(err)
		}
		if row.DecisionID != recorded[0].DecisionID || row.SentBackAt != nil {
			t.Errorf("an approved row was moved to decision %d and sent back at %v",
				row.DecisionID, row.SentBackAt)
		}
	})
}

// beforeHoldingBack runs something once, just before the first write that
// sends rows back.
type beforeHoldingBack struct {
	run   func()
	fired bool
}

func (h *beforeHoldingBack) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	if !h.fired && strings.HasPrefix(e.Query, "UPDATE") && strings.Contains(e.Query, "sent_back_at") {
		h.fired = true
		h.run()
	}
	return ctx
}

func (h *beforeHoldingBack) AfterQuery(context.Context, *bun.QueryEvent) {}
