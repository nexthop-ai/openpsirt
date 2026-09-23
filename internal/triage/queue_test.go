// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestTheQueueCarriesWhatAnApproverNeedsToJudge(t *testing.T) {
	// A reviewer works down a list. A list where judging each row means
	// opening it is a list that gets approved without being read — which is
	// the failure the queue exists to prevent, arriving by another route.
	each(t, func(t *testing.T, f *fixture) {
		f.claims(t, f.at())

		waiting, total, err := f.store.Queue(t.Context(), f.reviewer, false, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(waiting) != 1 {
			t.Fatalf("%d waiting (total %d), want 1", len(waiting), total)
		}
		if waiting[0].Reasoning == "" {
			t.Error("a row arrived with nothing to read")
		}
		if waiting[0].PreviouslyApproved {
			t.Error("a fresh claim reads as one that was agreed to before")
		}
	})
}

func TestSomethingComingBackSaysSo(t *testing.T) {
	// An approver meeting a claim again should know they are re-reading rather
	// than seeing it for the first time.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.claims(t, f.at())
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(ctx, f.triager, claimed.ClaimID, "Different reasoning entirely."); err != nil {
			t.Fatal(err)
		}

		waiting, _, err := f.store.Queue(ctx, f.reviewer, false, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 1 {
			t.Fatalf("%d waiting, want the revised one", len(waiting))
		}
		if !waiting[0].PreviouslyApproved {
			t.Error("a claim that came back after being agreed to reads as fresh")
		}
		if waiting[0].Reasoning != "Different reasoning entirely." {
			t.Errorf("the queue shows %q, not what now stands", waiting[0].Reasoning)
		}
	})
}

func TestAQueueShowsOnlyWorkTheReaderCanDo(t *testing.T) {
	// A work list containing work somebody cannot do teaches them to skip
	// rows, which is the opposite of what a review queue is for.
	each(t, func(t *testing.T, f *fixture) {
		f.claims(t, f.at())

		waiting, total, err := f.store.Queue(t.Context(), f.onlooker, false, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 0 || total != 0 {
			t.Errorf("somebody holding only a read role was shown %d rows (total %d)", len(waiting), total)
		}
	})
}

func TestAShortDeferralNeedsNobodyAndALongOneDoes(t *testing.T) {
	// A quick "not this sprint" is ordinary triage. Gating it would put every
	// routine act through a queue, which is how a queue stops being read.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const threshold = 30 * 24 * time.Hour

		soon := time.Now().UTC().Add(7 * 24 * time.Hour)
		short := triage.Proposal{
			Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Not this sprint.", By: f.proposer,
		}
		needs, err := f.store.NeedsApproval(ctx, short, threshold)
		if err != nil {
			t.Fatal(err)
		}
		if needs {
			t.Error("a week-long deferral was made to wait for a second person")
		}

		distant := time.Now().UTC().Add(200 * 24 * time.Hour)
		long := short
		long.DeferredUntil = &distant
		needs, err = f.store.NeedsApproval(ctx, long, threshold)
		if err != nil {
			t.Fatal(err)
		}
		if !needs {
			t.Error("a deferral of most of a year stood on its own")
		}
	})
}

func TestDeferringRepeatedlyStopsBeingShort(t *testing.T) {
	// Otherwise the exception swallows the rule: four consecutive twenty-nine
	// day deferrals are a year nobody approved.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const threshold = 30 * 24 * time.Hour
		nearly := 29 * 24 * time.Hour

		asking := func() triage.Proposal {
			until := time.Now().UTC().Add(nearly)
			return triage.Proposal{
				Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &until,
				Reasoning: "Still not this sprint.", By: f.proposer,
			}
		}

		first := asking()
		needs, err := f.store.NeedsApproval(ctx, first, threshold)
		if err != nil {
			t.Fatal(err)
		}
		if needs {
			t.Fatal("the first short deferral needed approval")
		}
		if _, err := f.store.Propose(ctx, f.triager, first); err != nil {
			t.Fatal(err)
		}

		// The second one asks for another twenty-nine days on a finding
		// already put off for twenty-nine, which is fifty-eight.
		needs, err = f.store.NeedsApproval(ctx, asking(), threshold)
		if err != nil {
			t.Fatal(err)
		}
		if !needs {
			t.Error("deferring twice for just under the threshold stayed unapproved")
		}
	})
}

func TestHidingRiskNeedsAgreementAndPuttingItBackDoesNot(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		for _, c := range []struct {
			outcome triage.Outcome
			needs   bool
		}{
			{triage.Affected, false},
			{triage.NotApplicable, true},
			{triage.WontFix, true},
		} {
			p := triage.Proposal{
				Place: f.at(), Outcome: c.outcome,
				Reasoning: "x", By: f.proposer,
			}
			if c.outcome == triage.NotApplicable {
				p.Justification = triage.CodeNotPresent
			}
			needs, err := f.store.NeedsApproval(ctx, p, 30*24*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if needs != c.needs {
				t.Errorf("%q needing approval = %v, want %v", c.outcome, needs, c.needs)
			}
		}
	})
}

func TestTheQueueLeavesOutWhatYouCannotApprove(t *testing.T) {
	// Approving your own claim is refused, because a control one person
	// completes alone is not one. A queue that lists them is a work list of
	// things the reader cannot do, and a list like that teaches somebody to
	// skip rows — which is the habit the queue exists to prevent.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.claims(t, f.at())

		// The proposer sees nothing waiting on them.
		if _, total, err := f.store.Queue(ctx, f.triager, false, 0, 50, 0); err != nil || total != 0 {
			t.Errorf("the proposer was shown their own claim: %d (%v)", total, err)
		}
		// Somebody else sees it, so the check above is not passing on an
		// empty queue.
		if _, total, err := f.store.Queue(ctx, f.reviewer, false, 0, 50, 0); err != nil || total != 1 {
			t.Errorf("a claim waiting for a second person was not shown to one: %d (%v)", total, err)
		}
	})
}

func TestYourOwnWaitingClaimsAreTheirOwnQuestion(t *testing.T) {
	// "What is waiting on me" and "what did I propose that nobody has agreed
	// to" are different questions, and somebody wants the second one to find
	// what is stuck. One statement answers both, so the count and the page
	// cannot disagree about which was asked.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.claims(t, f.at())

		mine, total, err := f.store.Queue(ctx, f.triager, true, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(mine) != 1 {
			t.Fatalf("the proposer found %d of their own waiting claims, want 1", total)
		}
		// And somebody else's own list does not contain it.
		if _, total, err := f.store.Queue(ctx, f.reviewer, true, 0, 50, 0); err != nil || total != 0 {
			t.Errorf("a claim appeared among somebody else's own: %d (%v)", total, err)
		}
	})
}

// The cumulative threshold counts a withdrawn deferral for as long as it
// actually held.
//
// Excluded outright, the threshold was defeated by withdrawing and deferring
// again: each span alone stayed under the line, the running total reset to
// zero every time, and a place stayed hidden indefinitely with no second
// person ever seeing it. Withdrawing needs nobody, so the whole loop is one
// person's.
func TestWithdrawingAndDeferringAgainDoesNotResetTheThreshold(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const threshold = 30 * 24 * time.Hour

		// A first deferral, under the line, then taken back after most of it
		// had run.
		soon := time.Now().UTC().Add(29 * 24 * time.Hour)
		first, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Not this sprint.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if first.NeedsApproval {
			t.Fatal("a deferral under the threshold was gated, so this tests nothing")
		}
		// Four weeks pass, moved here rather than waited for, and then it is
		// taken back. Withdrawing needs nobody, so the whole loop is one
		// person's.
		if _, err := f.db.DB.NewUpdate().Table("decision").
			Set("proposed_at = ?", time.Now().UTC().Add(-28*24*time.Hour)).
			Where("claim_id = ?", first.ClaimID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Withdraw(ctx, f.triager, first.ClaimID); err != nil {
			t.Fatal(err)
		}

		// The same place, put off again for another span under the line. The
		// two together are past it, and the second is what a second person
		// has to agree to.
		again := time.Now().UTC().Add(29 * 24 * time.Hour)
		needs, err := f.store.NeedsApproval(ctx, triage.Proposal{
			Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &again,
			Reasoning: "Not this sprint either.", By: f.proposer,
		}, threshold)
		if err != nil {
			t.Fatal(err)
		}
		if !needs {
			t.Error("deferring again after withdrawing needed nobody, so the " +
				"threshold resets every time somebody takes a deferral back")
		}
	})
}

// A claim's need for a second person is worked out where it is written.
//
// A field on the proposal, answered before the transaction opens and taken on
// trust, stores a claim as needing nobody under a policy that says it does
// wherever an administrator lowers the threshold between the answer and the
// write — with nothing reporting it. A caller stating the flag at all is the
// same shape as a binding deadline read outside the write.
func TestTheGateIsWorkedOutAgainstThePolicyWhenTheClaimLands(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// A deferral of ten days, and a deployment that gates anything past
		// seven.
		if err := setting.NewStore(f.db.DB).Set(ctx, setting.DeferralThreshold,
			(7 * 24 * time.Hour).String()); err != nil {
			t.Fatal(err)
		}
		until := time.Now().UTC().Add(10 * 24 * time.Hour)

		// Recorded as needing nobody, which is what a caller who read the
		// old policy would have said.
		made, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.Deferred, DeferredUntil: &until,
			Reasoning: "Not this sprint.", By: f.proposer,
			NeedsApproval: false,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !made.NeedsApproval {
			t.Error("a deferral past the deployment's threshold was stored as " +
				"needing nobody, on the caller's word")
		}
		if standing, _ := f.store.Applying(ctx, f.at()); standing != nil {
			t.Error("and it took effect at once")
		}
	})
}
