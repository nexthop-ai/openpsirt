// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// datedPast proposes a claim with a date still to come at one place, needing
// nobody, and then moves its date into the past: a date already gone is
// refused when written, and the date arriving is what the test is about.
func (f *fixture) datedPast(t *testing.T, identity string, outcome triage.Outcome) *triage.Decision {
	t.Helper()
	ctx := t.Context()
	soon := time.Now().UTC().Add(24 * time.Hour)
	past := time.Now().UTC().Add(-time.Hour)
	at := f.at()
	at.PlaceIdentity = identity
	p := triage.Proposal{Place: at, Outcome: outcome, Reasoning: "Not this sprint.", By: f.proposer}
	column := "deferred_until"
	if outcome.Commits() {
		p.CommittedTo = &soon
		column = "committed_to"
		if outcome == triage.UpgradeNeeded {
			p.UpgradeTo = "2.0"
		}
	} else {
		p.DeferredUntil = &soon
	}
	made, err := f.store.Propose(ctx, f.triager, p)
	if err != nil {
		t.Fatal(err)
	}
	// A promise is gated against the deadline its findings carry, and none
	// here carries one, so it waits for a second person. Agreed to, it waits
	// for nothing but its date.
	if made.State == triage.Proposed && made.NeedsApproval {
		if err := agreeTo(ctx, f.store, f.reviewer, made.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.DB.NewUpdate().Table("claim").
		Set(column+" = ?", past).
		Where("id = ?", made.ClaimID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return made
}

// listed is the claims one reason's list holds for somebody.
func (f *fixture) listed(t *testing.T, who access.Subject, filter triage.QueueFilter) []int64 {
	t.Helper()
	waiting, total, err := f.store.Queue(t.Context(), who, filter, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(waiting) != total {
		t.Fatalf("a page of %d under a total of %d", len(waiting), total)
	}
	ids := make([]int64, 0, len(waiting))
	for _, one := range waiting {
		ids = append(ids, one.Claim.ID)
	}
	return ids
}

func TestEachQueueReasonListsOnlyItsOwnKind(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		approval := f.at()
		approval.PlaceIdentity = "waiting-for-a-second-person"
		asked := f.claims(t, approval)
		expired := f.datedPast(t, "deferral-ran-out", triage.Deferred)
		upgrade := f.datedPast(t, "upgrade-date-passed", triage.UpgradeNeeded)
		patch := f.datedPast(t, "patch-date-passed", triage.PatchNeeded)
		// A decision the code moved out from under is its author's to
		// re-affirm, and is in none of these lists.
		moved := f.at()
		moved.PlaceIdentity = "moved-out-from-under"
		lapsed := f.claims(t, moved)
		if _, err := f.db.DB.NewUpdate().Model((*triage.Decision)(nil)).
			Set("state = ?", triage.LapsedState).
			Where("id = ?", lapsed.ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		for _, want := range []struct {
			reason triage.QueueReason
			claims []int64
		}{
			{"", []int64{asked.ClaimID}},
			{triage.ForApproval, []int64{asked.ClaimID}},
			{triage.DeferralExpired, []int64{expired.ClaimID}},
			{triage.FixDateMissed, []int64{patch.ClaimID, upgrade.ClaimID}},
		} {
			got := f.listed(t, f.reviewer, triage.QueueFilter{Reason: want.reason})
			if len(got) != len(want.claims) {
				t.Errorf("%q lists claims %v, want %v", want.reason, got, want.claims)
				continue
			}
			for i := range got {
				if got[i] != want.claims[i] {
					t.Errorf("%q lists claims %v, want %v", want.reason, got, want.claims)
					break
				}
			}
		}
	})
}

func TestAPassedDateIsShownToEverybodyWhoMayDecideIncludingItsProposer(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		expired := f.datedPast(t, "deferral-ran-out", triage.Deferred)
		missed := f.datedPast(t, "patch-date-passed", triage.PatchNeeded)
		approving := f.holding(t, "approves-only", map[int64][]access.Role{
			f.product: {access.PublicRead, access.Approver},
		})

		for _, reason := range []triage.QueueReason{triage.DeferralExpired, triage.FixDateMissed} {
			want := expired.ClaimID
			if reason == triage.FixDateMissed {
				want = missed.ClaimID
			}
			for _, who := range []struct {
				name    string
				subject access.Subject
				mine    bool
				shown   bool
			}{
				{"the proposer", f.triager, false, true},
				{"the proposer, asking for their own", f.triager, true, true},
				{"another triager", f.reviewer, false, true},
				{"another triager, asking for their own", f.reviewer, true, false},
				{"somebody who only reads", f.onlooker, false, false},
				{"somebody who may approve and not decide", approving, false, false},
			} {
				got := f.listed(t, who.subject, triage.QueueFilter{Reason: reason, Mine: who.mine})
				shown := len(got) == 1 && got[0] == want
				if shown != who.shown || len(got) > 1 {
					t.Errorf("%q for %s lists %v, want claim %d shown: %v",
						reason, who.name, got, want, who.shown)
				}
			}
		}
	})
}

func TestAPromisedPatchMovesByItsDateAlone(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		patch := f.datedPast(t, "patch-date-passed", triage.PatchNeeded)
		later := time.Now().UTC().AddDate(0, 0, 30).Truncate(time.Second)

		if _, _, err := f.store.Repromise(ctx, f.triager, patch.ClaimID, "3.0", later,
			"The backport slipped."); err == nil {
			t.Error("a promised patch was given a version to move to")
		}
		if _, _, err := f.store.Repromise(ctx, f.triager, patch.ClaimID, "", later,
			"The backport slipped."); err != nil {
			t.Fatalf("moving a promised patch's date: %v", err)
		}
		if got := f.listed(t, f.reviewer, triage.QueueFilter{Reason: triage.FixDateMissed}); len(got) != 0 {
			t.Errorf("a patch promised for a date still to come is listed as missed: %v", got)
		}

		upgrade := f.datedPast(t, "upgrade-date-passed", triage.UpgradeNeeded)
		if _, _, err := f.store.Repromise(ctx, f.triager, upgrade.ClaimID, "", later,
			"The release slipped."); err == nil {
			t.Error("a promised upgrade was left with no version to move to")
		}
	})
}
