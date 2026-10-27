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

// shipping is a build holding the fixture's issue in libfoo 1.2.3, for a decision
// that covers an open finding.
type shipping struct {
	in      build
	libfoo  int64
	opened  map[string]int64
	fixture *fixture
}

func (f *fixture) shipping(t *testing.T) *shipping {
	t.Helper()
	return &shipping{
		in: f.build(t, f.product, "2026.03"), libfoo: f.component(t, "libfoo", "1.2.3"),
		opened: map[string]int64{}, fixture: f,
	}
}

// closes closes the finding opened at an occurrence, which is what a kept promise
// does to what it covers.
func (s *shipping) closes(t *testing.T, identity string) {
	t.Helper()
	if _, err := s.fixture.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set(`"closed_at" = ?`, time.Now().UTC()).
		Where(`"id" = ?`, s.opened[identity]).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// datedPast proposes a decision with a date still to come at one occurrence, needing
// nobody, and then moves its date into the past: a date already gone is
// refused when written, and the date arriving is what the test is about. The
// occurrence holds an open finding the decision covers.
func (f *fixture) datedPast(t *testing.T, ships *shipping, identity string,
	outcome triage.Outcome) *triage.DecisionOccurrence {

	t.Helper()
	ctx := t.Context()
	soon := time.Now().UTC().Add(24 * time.Hour)
	past := time.Now().UTC().Add(-time.Hour)
	at := f.at()
	at.OccurrenceIdentity = identity
	// The finding has no consumer, so the decision is written against none.
	at.ConsumerUpstream = ""
	ships.opened[identity] = f.finds(t, ships.in, ships.libfoo, identity, access.Public)
	p := triage.Proposal{Occurrence: at, Outcome: outcome, Reasoning: "Not this sprint.", By: f.proposer}
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
		if err := agreeTo(ctx, f.store, f.reviewer, made.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.DB.NewUpdate().Table("decision").
		Set(column+" = ?", past).
		Where(`"id" = ?`, made.DecisionID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return made
}

// listed is the decisions one reason's list holds for somebody.
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
		ids = append(ids, one.Decision.ID)
	}
	return ids
}

func TestEachQueueReasonListsOnlyItsOwnKind(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ships := f.shipping(t)
		approval := f.at()
		approval.OccurrenceIdentity = "waiting-for-a-second-person"
		asked := f.decisions(t, approval)
		expired := f.datedPast(t, ships, "deferral-ran-out", triage.Deferred)
		upgrade := f.datedPast(t, ships, "upgrade-date-passed", triage.UpgradeNeeded)
		patch := f.datedPast(t, ships, "patch-date-passed", triage.PatchNeeded)
		// A decision the code moved out from under is its author's to
		// re-affirm, and is in none of these lists.
		moved := f.at()
		moved.OccurrenceIdentity = "moved-out-from-under"
		lapsed := f.decisions(t, moved)
		if _, err := f.db.DB.NewUpdate().Model((*triage.DecisionOccurrence)(nil)).
			Set(`"state" = ?`, triage.LapsedState).
			Where(`"id" = ?`, lapsed.ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		for _, want := range []struct {
			reason    triage.QueueReason
			decisions []int64
		}{
			{"", []int64{asked.DecisionID}},
			{triage.ForApproval, []int64{asked.DecisionID}},
			{triage.DeferralExpired, []int64{expired.DecisionID}},
			{triage.FixDateMissed, []int64{patch.DecisionID, upgrade.DecisionID}},
		} {
			got := f.listed(t, f.reviewer, triage.QueueFilter{Reason: want.reason})
			if len(got) != len(want.decisions) {
				t.Errorf("%q lists decisions %v, want %v", want.reason, got, want.decisions)
				continue
			}
			for i := range got {
				if got[i] != want.decisions[i] {
					t.Errorf("%q lists decisions %v, want %v", want.reason, got, want.decisions)
					break
				}
			}
		}
	})
}

func TestAPassedDateIsShownToEverybodyWhoMayDecideIncludingItsProposer(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ships := f.shipping(t)
		expired := f.datedPast(t, ships, "deferral-ran-out", triage.Deferred)
		missed := f.datedPast(t, ships, "patch-date-passed", triage.PatchNeeded)
		approving := f.holding(t, "approves-only", map[int64][]access.Role{
			f.product: {access.PublicRead, access.Approver},
		})

		for _, reason := range []triage.QueueReason{triage.DeferralExpired, triage.FixDateMissed} {
			want := expired.DecisionID
			if reason == triage.FixDateMissed {
				want = missed.DecisionID
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
					t.Errorf("%q for %s lists %v, want decision %d shown: %v",
						reason, who.name, got, want, who.shown)
				}
			}
		}
	})
}

func TestAPromisedPatchMovesByItsDateAlone(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		ships := f.shipping(t)
		patch := f.datedPast(t, ships, "patch-date-passed", triage.PatchNeeded)
		later := time.Now().UTC().AddDate(0, 0, 30).Truncate(time.Second)

		if _, _, err := f.store.Repromise(ctx, f.triager, patch.DecisionID, "3.0", later,
			"The backport slipped."); err == nil {
			t.Error("a promised patch was given a version to move to")
		}
		if _, _, err := f.store.Repromise(ctx, f.triager, patch.DecisionID, "", later,
			"The backport slipped."); err != nil {
			t.Fatalf("moving a promised patch's date: %v", err)
		}
		if got := f.listed(t, f.reviewer, triage.QueueFilter{Reason: triage.FixDateMissed}); len(got) != 0 {
			t.Errorf("a patch promised for a date still to come is listed as missed: %v", got)
		}

		upgrade := f.datedPast(t, ships, "upgrade-date-passed", triage.UpgradeNeeded)
		if _, _, err := f.store.Repromise(ctx, f.triager, upgrade.DecisionID, "", later,
			"The release slipped."); err == nil {
			t.Error("a promised upgrade was left with no version to move to")
		}
	})
}

func TestAKeptPromiseIsNotAMissedOne(t *testing.T) {
	// A kept promise closes the findings it covers and leaves its date and its
	// rows as they were, so its date passing says nothing about it.
	each(t, func(t *testing.T, f *fixture) {
		ships := f.shipping(t)
		kept := f.datedPast(t, ships, "patch-landed", triage.PatchNeeded)
		missed := f.datedPast(t, ships, "patch-still-open", triage.PatchNeeded)
		ships.closes(t, "patch-landed")

		got := f.listed(t, f.reviewer, triage.QueueFilter{Reason: triage.FixDateMissed})
		if len(got) != 1 || got[0] != missed.DecisionID {
			t.Errorf("missed fix dates list %v, want only decision %d and never the kept %d",
				got, missed.DecisionID, kept.DecisionID)
		}
	})
}

func TestMovingAPromisedPatchIsGatedByTheDeadlineOfWhatItCovers(t *testing.T) {
	// A patch records no builds of its own, so the deadline it is gated by is
	// read from the builds holding what it covers now.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		ships := f.shipping(t)
		patch := f.datedPast(t, ships, "patch-with-a-deadline", triage.PatchNeeded)
		due := time.Now().UTC().AddDate(0, 0, 30).Truncate(time.Second)
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"due_at" = ?`, due).
			Where(`"id" = ?`, ships.opened["patch-with-a-deadline"]).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		needs := func(t *testing.T) bool {
			t.Helper()
			var rows []triage.DecisionOccurrence
			if err := f.db.DB.NewSelect().Model(&rows).
				Where(`"de"."decision_id" = ?`, patch.DecisionID).Scan(ctx); err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 {
				t.Fatal("the decision wrote no rows")
			}
			return rows[0].NeedsApproval
		}

		inside := due.AddDate(0, 0, -10)
		if _, _, err := f.store.Repromise(ctx, f.triager, patch.DecisionID, "", inside,
			"The backport lands sooner."); err != nil {
			t.Fatal(err)
		}
		if needs(t) {
			t.Error("a patch moved to a date inside its deadline waits for a second person")
		}

		beyond := due.AddDate(0, 0, 30)
		if _, _, err := f.store.Repromise(ctx, f.triager, patch.DecisionID, "", beyond,
			"The backport slipped."); err != nil {
			t.Fatal(err)
		}
		if !needs(t) {
			t.Error("a patch moved past its deadline stands with nobody agreeing")
		}
		got := f.listed(t, f.reviewer, triage.QueueFilter{})
		if len(got) != 1 || got[0] != patch.DecisionID {
			t.Errorf("the approval list holds %v, want the moved patch %d", got, patch.DecisionID)
		}
	})
}

func TestAnExpiredDeferralWithARowTheReaderMayNotDecideIsNotOfferedToThem(t *testing.T) {
	// A new decision is made over the whole of the expired one, so whether any row of it
	// is out of the reader's reach is asked of the decision. A decision with one
	// undisclosed row is not offered to somebody who may decide about
	// disclosed work alone, and one wholly disclosed is.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		insider := f.privately(t)
		defers := func(occurrences ...triage.Occurrence) int64 {
			t.Helper()
			soon := time.Now().UTC().Add(24 * time.Hour)
			proposals := make([]triage.Proposal, 0, len(occurrences))
			for _, at := range occurrences {
				proposals = append(proposals, triage.Proposal{
					Occurrence: at, Outcome: triage.Deferred, DeferredUntil: &soon,
					Reasoning: "Not this sprint.", By: insider.ID,
				})
			}
			recorded, err := f.store.ProposeMany(ctx, insider, proposals)
			if err != nil {
				t.Fatal(err)
			}
			// A date already gone is refused when written, so it is moved
			// into the past after.
			if _, err := f.db.DB.NewUpdate().Table("decision").
				Set(`"deferred_until" = ?`, time.Now().UTC().Add(-time.Hour)).
				Where(`"id" = ?`, recorded[0].DecisionID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			return recorded[0].DecisionID
		}
		mixed := defers(f.occurrenceIn(f.product, "under-a", access.Private),
			f.occurrenceIn(f.product, "under-b", access.Public))
		disclosed := defers(f.occurrenceIn(f.product, "under-c", access.Public))

		outsider := f.holding(t, "public-decider", map[int64][]access.Role{
			f.product: {access.PublicRead, access.PublicTriage},
		})
		expired := triage.QueueFilter{Reason: triage.DeferralExpired}
		if got := f.listed(t, outsider, expired); len(got) != 1 || got[0] != disclosed {
			t.Errorf("somebody deciding disclosed work alone is offered decisions %v; want only %d"+
				" (the decision with an undisclosed row is %d)", got, disclosed, mixed)
		}
		// Somebody who may decide both is offered both, so the narrowing
		// above is the reach and not the decisions.
		if got := f.listed(t, insider, expired); len(got) != 2 {
			t.Errorf("somebody deciding at both visibilities is offered %v, want both decisions", got)
		}
		// The count is the length of the list it stands for.
		if _, n, err := f.store.Queue(ctx, outsider, expired, 0, 0); err != nil || n != 1 {
			t.Errorf("the expired deferrals counted for a disclosed decider are %d (%v), want 1", n, err)
		}
		if _, n, err := f.store.Queue(ctx, insider, expired, 0, 0); err != nil || n != 2 {
			t.Errorf("the expired deferrals counted for somebody deciding both are %d (%v), want 2", n, err)
		}
		if count, err := f.store.WaitingIn(ctx, outsider, f.product); err != nil || count != 0 {
			t.Errorf("the approval count beside the product is %d (%v), want 0", count, err)
		}
	})
}
