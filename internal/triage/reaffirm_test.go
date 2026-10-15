// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// judged claims something with a severity recorded against it, which is what a
// later re-affirmation compares itself to. The reason is one a severity bears
// on, so a rise escalates it.
func (f *fixture) judged(t *testing.T, at triage.Place, severity int) *triage.Decision {
	t.Helper()
	decision, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
		Place: at, Outcome: triage.NotApplicable,
		Justification: triage.CodeNotReachableByAdversary,
		Reasoning:     "Nothing an attacker sends reaches the parser.",
		By:            f.proposer, SeverityCenti: severity,
		NeedsApproval: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

// lapsed has a decision stop standing now, which is what a version moving
// under it does, without standing up a scan to move it.
func (f *fixture) lapsed(t *testing.T, id int64) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Model((*triage.Decision)(nil)).
		Set(`"state" = ?`, triage.LapsedState).
		Set(`"ended_at" = ?`, time.Now().UTC()).
		Where(`"id" = ?`, id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestReAffirmingAfterABumpNeedsNoSecondPerson(t *testing.T) {
	// Two people already agreed to this claim. A version bump is a prompt to
	// re-check rather than a new claim, and asking for full approval every
	// time produces rubber-stamping — which costs the control its meaning
	// everywhere, not only here.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), finding.SeverityScore("high"))
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		f.lapsed(t, agreed.ID)
		again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: agreed.ID, Place: moved,
			Reasoning: "Checked again at the new version; still not reached.",
			By:        f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if again.State != triage.Approved {
			t.Errorf("a re-affirmation of an agreed claim reads as %q", again.State)
		}
		// And it stands at the new versions.
		if standing, _ := f.store.Applying(ctx, moved); standing == nil {
			t.Error("the re-affirmed claim does not apply at the version it was re-made for")
		}
	})
}

func TestSeverityRisingSendsItBackForFullApproval(t *testing.T) {
	// The agreement was that this did not matter much. That is not an
	// agreement about what it has become.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), 400)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		// The world revises it upward, which is what an advisory sweep does.
		// Read by the store rather than handed in, so this is where it moves.
		if _, err := f.db.DB.NewUpdate().Table("vulnerability").
			Set(`"score_centi" = ?`, 950).
			Where(`"id" = ?`, f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		f.lapsed(t, agreed.ID)
		again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: agreed.ID, Place: moved,
			Reasoning: "Still not reached.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if again.State == triage.Approved {
			t.Error("a claim about a much worse issue inherited the old agreement")
		}
	})
}

func TestASeverityRiseEscalatesOnlyAClaimItBearsOn(t *testing.T) {
	// Code that is absent or never runs is not dangerous at any severity, and
	// a fix that already ships is there whatever the rating says. Every other
	// claim accepts a risk the severity measures, or argues against an attack
	// a higher rating may have made possible.
	cases := []struct {
		name          string
		outcome       triage.Outcome
		justification triage.Justification
		mitigation    string
		fixedVersion  string
		escalates     bool
	}{
		{name: "component not present", outcome: triage.NotApplicable,
			justification: triage.ComponentNotPresent},
		{name: "code not present", outcome: triage.NotApplicable,
			justification: triage.CodeNotPresent},
		{name: "not in execute path", outcome: triage.NotApplicable,
			justification: triage.CodeNotInExecutePath},
		{name: "already fixed", outcome: triage.AlreadyFixed, fixedVersion: "1.2.3-4"},
		{name: "not reachable by adversary", outcome: triage.NotApplicable,
			justification: triage.CodeNotReachableByAdversary, escalates: true},
		{name: "mitigations exist", outcome: triage.NotApplicable,
			justification: triage.MitigationsExist, mitigation: "The port is firewalled.",
			escalates: true},
		{name: "won't fix", outcome: triage.WontFix, escalates: true},
	}
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := make([]*triage.Decision, len(cases))
		for i, c := range cases {
			at := f.at()
			at.PlaceIdentity = "place-" + c.name
			decision, err := f.store.Propose(ctx, f.triager, triage.Proposal{
				Place: at, Outcome: c.outcome, Justification: c.justification,
				Mitigation: c.mitigation, FixedVersion: c.fixedVersion,
				Reasoning: "Judged at the old version.", By: f.proposer,
				SeverityCenti: 400, NeedsApproval: true,
			})
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if err := agreeTo(ctx, f.store, f.reviewer, decision.ClaimID, ""); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			agreed[i] = decision
		}
		if _, err := f.db.DB.NewUpdate().Table("vulnerability").
			Set(`"score_centi" = ?`, 950).
			Where(`"id" = ?`, f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		for i, c := range cases {
			moved := f.at()
			moved.PlaceIdentity = "place-" + c.name
			moved.ComponentUpstream = "1.2.4"
			f.lapsed(t, agreed[i].ID)
			again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
				PreviousID: agreed[i].ID, Place: moved,
				Reasoning: "Checked again at the new version.", By: f.proposer,
			})
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if waits := again.State != triage.Approved; waits != c.escalates {
				t.Errorf("%s: after a severity rise it waits for a second person = %v, want %v",
					c.name, waits, c.escalates)
			}
		}
	})
}

func TestARatingMadeHereAlsoSendsItBackForFullApproval(t *testing.T) {
	// The same rule, asked of the half that is ours. An assessment writes the
	// word and never the published score, so a comparison reading that score
	// alone saw nothing move: an issue published `high` with no vector scored
	// zero before somebody rated it critical and zero afterwards, and a
	// dismissal agreed to once was re-affirmed with nobody else.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), finding.SeverityScore("high"))
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		// Rated by this product rather than by the world, which is the case
		// the published score cannot see.
		if _, err := f.db.DB.NewInsert().Model(&finding.IssueRating{
			VulnerabilityID: f.issue, ProductID: f.product, Severity: "critical",
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		f.lapsed(t, agreed.ID)
		again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: agreed.ID, Place: moved,
			Reasoning: "Still not reached.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if again.State == triage.Approved {
			t.Error("a claim about an issue rated worse here inherited the old agreement")
		}
	})
}

func TestNothingIsCarriedFromAClaimNobodyAgreedTo(t *testing.T) {
	// Otherwise a version bump manufactures an approval out of nothing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Baselined at the fixture's own severity, so only the "nobody
		// agreed" rule can produce the refusal. At 700 the severity rule
		// fired first and this test passed through that arm instead —
		// deleting the rule it is named for left it green.
		neverAgreed := f.judged(t, f.at(), finding.SeverityScore("high"))

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		f.lapsed(t, neverAgreed.ID)
		again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: neverAgreed.ID, Place: moved,
			Reasoning: "Still true.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if again.State == triage.Approved {
			t.Error("a claim nobody ever agreed to came back approved")
		}
	})
}

func TestALapsedClaimNobodyAgreedToIsNotPreAgreed(t *testing.T) {
	// A claim lapses from proposed as well as from approved — the code moved
	// out from under it either way — so "it lapsed" says nothing about whether
	// anybody ever agreed to it. Reading the state as evidence of agreement
	// let one person dismiss a finding alone: propose it, wait for a version
	// bump to lapse it, re-affirm. The re-affirmation needed nobody, stood the
	// moment it was written, and appeared in no review queue.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// The fixture's own severity, so the severity rule cannot answer
		// first: what this test is named for is that a lapse is not an
		// agreement, and at 700 it was the severity arm that refused.
		neverAgreed := f.judged(t, f.at(), finding.SeverityScore("high"))
		// Lapse's own effect when the versions move, without standing up a
		// scan to move them.
		if _, err := f.db.DB.NewUpdate().Model((*triage.Decision)(nil)).
			Set(`"state" = ?`, triage.LapsedState).
			Where(`"id" = ?`, neverAgreed.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: neverAgreed.ID, Place: moved,
			Reasoning: "Still true at the new version.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if again.State == triage.Approved {
			t.Error("a lapsed claim nobody agreed to came back approved")
		}
		if !again.NeedsApproval {
			t.Error("the re-affirmation needs nobody, so one person dismissed this alone")
		}
		// The two consequences that matter, asked of the code that acts on
		// them rather than of the row: it must not suppress the finding, and
		// it must be in the queue where somebody sees it.
		if standing, _ := f.store.Applying(ctx, moved); standing != nil {
			t.Error("a claim waiting for a second person is already suppressing the finding")
		}
		waiting, _, err := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range waiting {
			if row.Decision.ID == again.ID {
				found = true
			}
		}
		if !found {
			t.Error("the re-affirmation is in no review queue, so nobody is asked about it")
		}
	})
}

func TestRepetitionAloneChangesNothing(t *testing.T) {
	// Deliberately left out. A count of re-affirmations would fire on nothing
	// having changed, which every other rule here refuses to do.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Agreed to at what the issue scores, which is what the handler
		// records: the comparison is "has it risen since", so a claim stored
		// at some other number would be testing the arithmetic rather than
		// the rule.
		previous := f.judged(t, f.at(), finding.SeverityScore("high"))
		if err := agreeTo(ctx, f.store, f.reviewer, previous.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		at := f.at()
		for i, version := range []string{"1.2.4", "1.2.5", "1.2.6", "1.2.7"} {
			at.ComponentUpstream = version
			f.lapsed(t, previous.ID)
			again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
				PreviousID: previous.ID, Place: at,
				Reasoning: "Checked again; still not reached.", By: f.proposer,
			})
			if err != nil {
				t.Fatal(err)
			}
			if again.State != triage.Approved {
				t.Errorf("re-affirmation %d was sent for full approval on repetition alone", i+1)
			}
			previous = again
		}
	})
}

func TestAWithdrawnAgreementIsNotResurrectedByAVersionBump(t *testing.T) {
	// The case the state check actually guards. A withdrawn decision still has
	// its approval rows — that is deliberate, because who agreed and to what
	// is part of the record — so carrying an agreement forward without asking
	// what state it is in would undo a withdrawal with a version bump.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), finding.SeverityScore("high"))
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		// Somebody thought better of it.
		if err := f.store.Withdraw(ctx, f.triager, agreed.ClaimID); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		if _, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: agreed.ID, Place: moved,
			Reasoning: "Trying again.", By: f.proposer,
		}); err == nil {
			t.Error("a withdrawn claim was re-affirmed")
		}
		if standing, _ := f.store.Applying(ctx, moved); standing != nil {
			t.Error("a withdrawn agreement came back through a version bump")
		}
	})
}

// A carried agreement is recorded as carried.
//
// A re-affirmation states its own reasoning — that is the point of it — and
// stands on the agreement its predecessor had. Written as an ordinary
// approval it said the earlier approver had agreed, today, to words they have
// never seen: the register, the audit list and the approvals of the claim all
// reported an agreement that did not happen, and the person whose name was on
// it could not have contradicted it because nothing said it was theirs to
// contradict.
func TestACarriedAgreementSaysItWasCarried(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), finding.SeverityScore("high"))
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		f.lapsed(t, agreed.ID)
		again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: agreed.ID, Place: moved,
			Reasoning: "Checked again at the new version; still not reached.",
			By:        f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if again.State != triage.Approved {
			t.Fatalf("a re-affirmation of an agreed claim reads as %q", again.State)
		}

		carried, err := f.store.Approvals(ctx, f.triager, again.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(carried) != 1 {
			t.Fatalf("the re-affirmed claim holds %d agreements", len(carried))
		}
		if carried[0].CarriedFrom == nil {
			t.Fatal("the carried agreement reads as one given for these words")
		}

		// And the agreement it names is the one somebody actually gave.
		first, err := f.store.Approvals(ctx, f.triager, agreed.ClaimID)
		if err != nil {
			t.Fatal(err)
		}
		if len(first) != 1 || *carried[0].CarriedFrom != first[0].ID {
			t.Errorf("it names agreement %v, and the one given was %+v",
				carried[0].CarriedFrom, first)
		}
		// The agreement given for the original names nothing: it was given.
		if first[0].CarriedFrom != nil {
			t.Error("an agreement somebody gave reads as carried")
		}
	})
}

func TestOnlyItsMakerReaffirmsALapsedDecisionAtItsOwnPlace(t *testing.T) {
	// Each refusal is reached by a request that passes every other check.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), finding.SeverityScore("high"))
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		reaffirm := func(as access.Subject, by int64, at triage.Place) error {
			_, err := f.store.Reaffirm(ctx, as, triage.Reaffirmation{
				PreviousID: agreed.ID, Place: at,
				Reasoning: "Checked again at the new version.", By: by,
			})
			return err
		}

		// Still standing: re-made elsewhere, it would carry the agreement to a
		// place no second person saw.
		if err := reaffirm(f.triager, f.proposer, moved); err == nil ||
			!strings.Contains(err.Error(), "has not lapsed") {
			t.Errorf("a decision still standing was re-affirmed: %v", err)
		}
		if standing, _ := f.store.Applying(ctx, moved); standing != nil {
			t.Error("a refused re-affirmation stands at the new version")
		}

		f.lapsed(t, agreed.ID)
		if err := reaffirm(f.reviewer, f.approver, moved); err == nil ||
			!strings.Contains(err.Error(), "only the person who made") {
			t.Errorf("somebody other than its maker re-affirmed it: %v", err)
		}
		elsewhere := moved
		elsewhere.PlaceIdentity = "another-place"
		if err := reaffirm(f.triager, f.proposer, elsewhere); err == nil ||
			!strings.Contains(err.Error(), "different place") {
			t.Errorf("it was re-affirmed at another place: %v", err)
		}

		// Something decided at the place since replaces it.
		later := f.at()
		later.ComponentUpstream = "1.2.5"
		f.claims(t, later)
		if err := reaffirm(f.triager, f.proposer, moved); err == nil ||
			!strings.Contains(err.Error(), "decided at that place since") {
			t.Errorf("a decision replaced since was re-affirmed: %v", err)
		}
	})
}

func TestSomebodyWhoWroteAnyOfAClaimsReasoningMayNotAgreeToIt(t *testing.T) {
	// The words agreed to are the latest revision's, and the control is that
	// the person agreeing is not one who argued the claim. A reviewer who
	// revised it, then saw the proposer revise it back, wrote part of it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed := f.claims(t, f.at())
		if _, err := f.store.Revise(ctx, f.reviewer, claimed.ClaimID,
			"The parser is compiled out of this image."); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Revise(ctx, f.triager, claimed.ClaimID,
			"The parser is never reached: we only call the encoder."); err != nil {
			t.Fatal(err)
		}
		// The list of what waits for them does not offer it either, nor count it.
		waiting, total, err := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 0 || len(waiting) != 0 {
			t.Errorf("somebody who wrote part of the reasoning is offered %d claims to agree to", total)
		}
		third := f.holding(t, "third", map[int64][]access.Role{f.product: {access.PublicTriage}})
		if _, total, err := f.store.Queue(ctx, third, triage.QueueFilter{}, 50, 0); err != nil || total != 1 {
			t.Errorf("somebody who wrote none of it is offered %d claims to agree to: %v", total, err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); !errors.Is(err, triage.ErrSamePerson) {
			t.Errorf("somebody who wrote part of the reasoning agreed to it: %v", err)
		}
		if standing, _ := f.store.Applying(ctx, f.at()); standing != nil {
			t.Error("the claim stands on its own author's agreement")
		}
	})
}

func TestADecisionUndisclosedSinceIsNotReaffirmedBySomebodyWhoMayNotArgueIt(t *testing.T) {
	// Authorized against the row as it stands: a decision whose place is
	// undisclosed now is not re-made by somebody triaging disclosed work,
	// one row or the whole claim.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), finding.SeverityScore("high"))
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		f.lapsed(t, agreed.ID)
		if _, err := f.db.DB.NewUpdate().Model((*triage.Decision)(nil)).
			Set(`"visibility" = ?`, access.Private).Where(`"id" = ?`, agreed.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		if _, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: agreed.ID, Place: moved,
			Reasoning: "Checked again at the new version.", By: f.proposer,
		}); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("one row undisclosed since was re-affirmed: %v", err)
		}
		if _, err := f.store.ReaffirmClaim(ctx, f.triager, triage.ReaffirmingClaim{
			PreviousClaimID: agreed.ClaimID,
			Reasoning:       "Checked again at the new version.", By: f.proposer,
			Bounds: triage.DefaultBounds(),
		}); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("a claim with a row undisclosed since was re-affirmed: %v", err)
		}
	})
}

func TestOnlyAPersonIsAnsweredAboutWhatTheyMustRevisit(t *testing.T) {
	// A key reaches neither list. "Here is nothing" and "you cannot ask" are
	// different statements, and a key is told the second.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		key := access.NewPipeline(9, "nightly", access.Scope{ProductID: f.product})
		if _, _, err := f.store.ToReaffirm(ctx, key, f.product, 50, 0); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a key read what is its to re-affirm: %v", err)
		}
		if _, _, err := f.store.RepeatsPage(ctx, key, f.product, 0, 50, 0); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a key read which deferrals repeat: %v", err)
		}
	})
}

func TestAnAgreementIsNotCarriedFromSomebodyWhoWroteAnyOfTheEarlierClaim(t *testing.T) {
	// A carried agreement was given to the earlier claim's words, so the
	// second-person rule is asked of the earlier claim. Its approver wrote part
	// of those words here, which an agreement given today is refused for and
	// one on record from before may still hold.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), finding.SeverityScore("high"))
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewInsert().Model(&triage.Revision{
			ClaimID: agreed.ClaimID, Body: "Nothing an attacker sends is parsed.",
			WrittenBy: f.approver, WrittenAt: time.Now().UTC().Add(-time.Hour),
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		f.lapsed(t, agreed.ID)
		_, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: agreed.ID, Place: moved,
			Reasoning: "Checked again at the new version; still not reached.",
			By:        f.proposer,
		})
		if !errors.Is(err, triage.ErrSamePerson) {
			t.Errorf("an agreement from somebody who wrote part of the earlier claim was carried: %v", err)
		}
		if standing, _ := f.store.Applying(ctx, moved); standing != nil {
			t.Error("the re-affirmed claim stands on that agreement")
		}
	})
}
