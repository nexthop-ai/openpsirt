// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"

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
			Set("score_centi = ?", 950).
			Where("id = ?", f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
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
			Set("score_centi = ?", 950).
			Where("id = ?", f.issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		for i, c := range cases {
			moved := f.at()
			moved.PlaceIdentity = "place-" + c.name
			moved.ComponentUpstream = "1.2.4"
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
			Set("state = ?", triage.LapsedState).
			Where("id = ?", neverAgreed.ID).Exec(ctx); err != nil {
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
		waiting, _, err := f.store.Queue(ctx, f.reviewer, false, 0, 50, 0)
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
		again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: agreed.ID, Place: moved,
			Reasoning: "Trying again.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if again.State == triage.Approved {
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
