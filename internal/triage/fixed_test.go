// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// alreadyFixed is a claim that whoever packages the component has already
// shipped the fix, which is the outcome a backported patch needs: it does not
// move the upstream version, so nothing here can see it.
func (f *fixture) alreadyFixed(t *testing.T, at triage.Place, version string) triage.Proposal {
	t.Helper()
	return triage.Proposal{
		Place: at, Outcome: triage.AlreadyFixed,
		FixedVersion: version,
		Reasoning:    "Alpine backported this; the tracker names the release it landed in.",
		By:           f.proposer, NeedsApproval: true,
	}
}

func TestAClaimThatTheFixIsAlreadyHereNeedsTheVersionItArrivedIn(t *testing.T) {
	// This outcome asserts a fact rather than a judgment: whoever packages the
	// component either states the release the fix arrived in or does not.
	// Without it the claim is "trust me", which is the one thing an outcome
	// that hides risk on a matter of fact must not be able to say.
	each(t, func(t *testing.T, f *fixture) {
		_, err := f.store.Propose(t.Context(), f.triager, f.alreadyFixed(t, f.at(), ""))
		if err == nil {
			t.Fatal("a claim that the fix is already here was recorded with nothing to check it against")
		}
		if !strings.Contains(err.Error(), "version") {
			t.Errorf("the refusal does not say what is missing: %v", err)
		}

		decision, err := f.store.Propose(t.Context(), f.triager, f.alreadyFixed(t, f.at(), "1.37.0-r31"))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Claim.FixedVersion == nil || *decision.Claim.FixedVersion != "1.37.0-r31" {
			t.Errorf("the version the fix arrived in was not kept: %v", decision.Claim.FixedVersion)
		}
	})
}

func TestOnlyThatClaimCarriesAVersionTheFixArrivedIn(t *testing.T) {
	// The same rule the other outcome-specific fields hold to. A value that is
	// meaningless where it sits is worse than an absent one: it reads as
	// having been considered.
	each(t, func(t *testing.T, f *fixture) {
		for _, outcome := range []triage.Outcome{triage.Affected, triage.WontFix} {
			_, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
				Place: f.at(), Outcome: outcome,
				FixedVersion: "1.37.0-r31",
				Reasoning:    "Recorded against the wrong outcome.",
				By:           f.proposer, NeedsApproval: true,
			})
			if err == nil {
				t.Errorf("%q was recorded claiming a fix has arrived", outcome)
			}
		}
	})
}

func TestAClaimThatTheFixIsAlreadyHereAlwaysNeedsASecondPerson(t *testing.T) {
	// It hides risk, so it is gated like every other suppression, and it gets
	// no part of the exemption a short deferral has. That exemption exists
	// because "not this sprint" is ordinary triage; this is a claim that
	// something is over, and the finding stops being visible on one person's
	// word if nobody checks it.
	each(t, func(t *testing.T, f *fixture) {
		if !triage.AlreadyFixed.HidesRisk() {
			t.Fatal("a claim that the fix is already here leaves the issue in the working queue")
		}
		// A threshold generous enough to exempt any deferral, to show that
		// what exempts one has no reach here.
		needs, err := f.store.NeedsApproval(t.Context(),
			f.alreadyFixed(t, f.at(), "1.37.0-r31"), 365*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if !needs {
			t.Error("it was recorded as standing on one person's say-so")
		}
	})
}

func TestAPackagingRevisionDoesNotLapseTheClaimAndAnUpstreamMoveDoes(t *testing.T) {
	// The crux of the outcome. What it claims is that this packaging of
	// this upstream version carries the patch, so a later packaging
	// revision of the same upstream version still does — the decision is
	// keyed on the upstream version alone, which is what makes that true
	// without anything comparing one revision against another.
	//
	// An upstream move is different code, and the claim says nothing about
	// it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed, err := f.store.Propose(ctx, f.triager, f.alreadyFixed(t, f.at(), "1.37.0-r31"))
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		// The same upstream version, packaged again. Nothing about the claim
		// has stopped being true.
		revised := f.at()
		if standing, err := f.store.Applying(ctx, revised); err != nil || standing == nil {
			t.Error("a packaging revision of the same upstream version lost the claim")
		}

		// A different upstream version is different code.
		moved := f.at()
		moved.ComponentUpstream = "1.38.0"
		standing, err := f.store.Applying(ctx, moved)
		if err != nil {
			t.Fatal(err)
		}
		if standing != nil {
			t.Error("the claim still stands over an upstream version it was never made about")
		}
	})
}

func TestReAffirmingCarriesEverythingTheClaimRestsOn(t *testing.T) {
	// A re-affirmation says the same claim still holds, so a field the outcome
	// requires is as required as it was the first time. Dropping one does not
	// weaken the claim — it makes the re-affirmation refuse itself, for want
	// of a value nobody removed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed, err := f.store.Propose(ctx, f.triager, f.alreadyFixed(t, f.at(), "1.37.0-r31"))
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.38.0"
		again, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: claimed.ID, Place: moved,
			Reasoning: "Checked again: the newer package carries it too.",
			By:        f.proposer,
		})
		if err != nil {
			t.Fatalf("re-affirming a claim that the fix is already here: %v", err)
		}
		if again.Claim.FixedVersion == nil {
			t.Fatal("the re-affirmed claim carries no version to check it against")
		}
	})
}

func TestReAffirmingCarriesWhatStopsIt(t *testing.T) {
	// The same defect on the field beside it, which predates this outcome: a
	// dismissal resting on mitigations names what stops it, and the
	// re-affirmation dropped the name and was refused by the rule that
	// requires it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		claimed, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Place: f.at(), Outcome: triage.NotApplicable,
			Justification: triage.MitigationsExist,
			Mitigation:    "The management interface is not reachable from outside.",
			Reasoning:     "Nothing routes to it.",
			By:            f.proposer, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, claimed.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		moved := f.at()
		moved.ComponentUpstream = "1.2.4"
		if _, err := f.store.Reaffirm(ctx, f.triager, triage.Reaffirmation{
			PreviousID: claimed.ID, Place: moved,
			Reasoning: "Still not reachable at the new version.",
			By:        f.proposer,
		}); err != nil {
			t.Fatalf("re-affirming a dismissal that rests on mitigations: %v", err)
		}
	})
}

func TestNothingWithADateMayBeSaidAboutATag(t *testing.T) {
	// A tag was built once and is what somebody received. An outcome that
	// names a date is a statement about a thing that will not move: a deferral
	// says somebody will look again when nothing will have changed, and a
	// promise to act says work will land in a release that is closed.
	//
	// The three refused are exactly the three that store a date, which is why
	// the check asks that rather than keeping a list.
	each(t, func(t *testing.T, f *fixture) {
		at := f.at()
		at.OnTag = true
		soon := time.Now().UTC().AddDate(0, 0, 30)

		for _, c := range []struct {
			outcome triage.Outcome
			set     func(*triage.Proposal)
		}{
			{triage.Deferred, func(p *triage.Proposal) { p.DeferredUntil = &soon }},
			{triage.UpgradeNeeded, func(p *triage.Proposal) {
				p.UpgradeTo, p.CommittedTo = "3.9.0", &soon
			}},
			{triage.PatchNeeded, func(p *triage.Proposal) { p.CommittedTo = &soon }},
		} {
			p := triage.Proposal{
				Place: at, Outcome: c.outcome,
				Reasoning: "Not this release.", By: f.proposer,
			}
			c.set(&p)
			if _, err := f.store.Propose(t.Context(), f.triager, p); err == nil {
				t.Errorf("%q was accepted against a release that cannot change", c.outcome)
			}
		}

		// And what is true of it can still be said, which is the whole point
		// of triaging a tag.
		for _, outcome := range []triage.Outcome{
			triage.Affected, triage.WontFix,
		} {
			place := at
			place.PlaceIdentity = string(outcome)
			if _, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
				Place: place, Outcome: outcome,
				Reasoning: "What is true of this release.", By: f.proposer,
			}); err != nil {
				t.Errorf("%q was refused against a tag: %v", outcome, err)
			}
		}
	})
}
