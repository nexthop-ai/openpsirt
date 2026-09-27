// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// openAt opens the fixture's issue at a place in a build of the fixture's
// product, and answers with the place a decision covering it is made at.
func (f *fixture) openAt(t *testing.T, identity string) triage.Place {
	t.Helper()
	in := f.build(t, f.product, "rated-"+identity)
	f.finds(t, in, f.component(t, "lib-"+identity, "1.2.3"), identity, access.Public)
	at := f.at()
	at.PlaceIdentity = identity
	at.ConsumerUpstream = ""
	return at
}

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
		agreed := f.judged(t, f.openAt(t, "band"), 710)
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
		agreed := f.judged(t, f.openAt(t, "agreed"), 710)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		proposed := f.judged(t, f.openAt(t, "proposed"), 710)

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
		agreed := f.judged(t, f.openAt(t, "unrated"), 0)
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
			Place: f.openAt(t, "absent"), Outcome: triage.NotApplicable,
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
		agreed := f.judged(t, f.openAt(t, "elsewhere"), 300)
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

func TestARiseLapsesNothingThatCoversNothingOpen(t *testing.T) {
	// A claim covering nothing is not one anybody relies on. Lapsed for a
	// rating, its proposer would be told the finding is open again when none
	// is, and re-affirming it would find nothing to re-make.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), 300)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, agreed.ID); state != triage.Approved {
			t.Errorf("a claim covering nothing open is %q after it was rated worse", state)
		}
	})
}

func TestARiseLeavesAClaimThatHidesNothingOrIsAboutIdentity(t *testing.T) {
	// "This affects us" is only strengthened by a rise, and a wrong match is
	// not a judgment about risk.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		var made []*triage.Decision
		for identity, outcome := range map[string]triage.Outcome{
			"affected": triage.Affected, "mismatched": triage.Mismatched,
		} {
			p := triage.Proposal{
				Place: f.openAt(t, identity), Outcome: outcome,
				Reasoning: "Judged at the old rating.", By: f.proposer,
				SeverityCenti: 300, NeedsApproval: true,
			}
			if outcome == triage.Mismatched {
				p.Justification = triage.ComponentNotPresent
			}
			decision, err := f.store.Propose(ctx, f.triager, p)
			if err != nil {
				t.Fatalf("%s: %v", identity, err)
			}
			if err := agreeTo(ctx, f.store, f.reviewer, decision.ClaimID, ""); err != nil {
				t.Fatalf("%s: %v", identity, err)
			}
			made = append(made, decision)
		}
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		for _, decision := range made {
			if state := f.stateOf(t, decision.ID); state == triage.LapsedState {
				t.Errorf("decision %d lapsed after a rise, and the rise bears on nothing it says",
					decision.ID)
			}
		}
	})
}

func TestAScanOfOneProductLapsesAClaimInAnother(t *testing.T) {
	// An issue is one row for the deployment. A build in one product raising
	// its rating outgrows a claim another product made about it, so the sweep
	// after a scan asks about the issues the build has open in any product.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other := f.secondProduct(t)
		there := f.build(t, other, "theirs-1")
		f.finds(t, there, f.component(t, "lib-theirs", "1.2.3"), "place-theirs", access.Public)
		who := f.holding(t, "their-triager", map[int64][]access.Role{other: {access.PublicTriage}})
		at := f.at()
		at.ProductID, at.PlaceIdentity, at.ConsumerUpstream = other, "place-theirs", ""
		theirs, err := f.store.Propose(ctx, who, triage.Proposal{
			Place: at, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotReachableByAdversary,
			Reasoning:     "Nothing an attacker sends reaches it.", By: who.ID,
			SeverityCenti: 300, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}

		here := f.build(t, f.product, "ours-1")
		f.finds(t, here, f.component(t, "lib-ours", "1.2.3"), "place-ours", access.Public)
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{OpenIn: here.target}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, theirs.ID); state != triage.LapsedState {
			t.Errorf("a claim in another product is %q after a scan here rated its issue worse", state)
		}
	})
}

func TestASiblingClaimAtAnotherVersionReplacesNothing(t *testing.T) {
	// Two streams at two versions hold sibling claims at one place, keyed
	// apart by the versions. One lapsing leaves it the proposer's to
	// re-affirm, whichever was made later.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		old := f.build(t, f.product, "sibling-old")
		f.finds(t, old, f.component(t, "lib-sibling", "1.2.3"), "place-sibling", access.Public)
		current := f.build(t, f.product, "sibling-new")
		f.finds(t, current, f.component(t, "lib-sibling-next", "1.2.4"), "place-sibling", access.Public)

		at := f.at()
		at.PlaceIdentity, at.ConsumerUpstream = "place-sibling", ""
		first := f.judged(t, at, 300)
		at.ComponentUpstream = "1.2.4"
		second := f.judged(t, at, 300)
		if second.ID < first.ID {
			t.Fatal("the sibling was not written after the claim it stands beside")
		}
		if _, err := f.db.DB.NewUpdate().Table("decision").
			Set("state = ?", triage.LapsedState).Set("ended_at = ?", time.Now().UTC()).
			Set("live_key = NULL").Where("id = ?", first.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		listed, total, err := f.store.ToReaffirm(ctx, f.triager, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(listed) != 1 || listed[0].Claim.ID != first.ClaimID {
			t.Errorf("listed %d of %d, want the lapsed claim beside its standing sibling",
				len(listed), total)
		}
	})
}
