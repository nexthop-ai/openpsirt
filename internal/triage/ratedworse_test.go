// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// rateIssue sets the published score of the fixture's issue.
func (f *fixture) rateIssue(t *testing.T, centi int) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Table("vulnerability").
		Set("score_centi = ?", centi).
		Where("id = ?", f.issue).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestARiseWithinABandLapsesNothing(t *testing.T) {
	// A rescoring inside a band is the same judgment about the same issue.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), 710)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 890)
		lapsed, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{})
		if err != nil {
			t.Fatal(err)
		}
		if lapsed.Rows != 0 || f.stateOf(t, agreed.ID) != triage.Approved {
			t.Errorf("a rise from 7.1 to 8.9 lapsed %d rows", lapsed.Rows)
		}
	})
}

func TestARiseIntoAHigherBandLapsesAgreedAndProposedClaims(t *testing.T) {
	// Proposed as well as approved: agreed to afterwards, a claim made against
	// the lower rating would stand on a baseline that is already wrong.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), 710)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.at()
		elsewhere.PlaceIdentity = "another-place"
		proposed := f.judged(t, elsewhere, 710)

		f.rateIssue(t, 950)
		lapsed, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{})
		if err != nil {
			t.Fatal(err)
		}
		for name, id := range map[string]int64{"agreed": agreed.ID, "proposed": proposed.ID} {
			if state := f.stateOf(t, id); state != triage.LapsedState {
				t.Errorf("the %s claim is %q after high became critical", name, state)
			}
		}
		if len(lapsed.Told) != 1 || !lapsed.Told[0].RatedWorse || lapsed.Told[0].Rows != 2 {
			t.Errorf("told %+v, want the proposer once about both rows, as rated worse", lapsed.Told)
		}
	})
}

func TestAClaimAboutAnUnratedIssueIsMeasuredFromMedium(t *testing.T) {
	// Unknown is not harmless, and not the lowest either: the way a deadline
	// reads an unrated issue.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.rateIssue(t, 0)
		agreed := f.judged(t, f.at(), 0)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 500)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, agreed.ID); state != triage.Approved {
			t.Errorf("rating an unrated issue medium left the claim %q", state)
		}
		f.rateIssue(t, 750)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, agreed.ID); state != triage.LapsedState {
			t.Errorf("rating an unrated issue high left the claim %q", state)
		}
	})
}

func TestARiseLeavesAClaimItDoesNotBearOn(t *testing.T) {
	// Absent code is not dangerous at any severity.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		absent, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.NotApplicable,
			Justification: triage.CodeNotPresent,
			Reasoning:     "The driver is not built.", By: f.proposer,
			SeverityCenti: 300, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, absent.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, absent.ID); state != triage.Approved {
			t.Errorf("a claim that the code is absent is %q after low became critical", state)
		}
	})
}

func TestARiseInAnotherProductLapsesNothingHere(t *testing.T) {
	// Narrowed to one product, the sweep leaves another's claims alone.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), 300)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{
			ProductID: f.product + 1000,
		}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, agreed.ID); state != triage.Approved {
			t.Errorf("a sweep of another product left this claim %q", state)
		}
	})
}
