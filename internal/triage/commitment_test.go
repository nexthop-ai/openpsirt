// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// A promise to act is gated by where it lands against the deadline the work
// already has, not by whether it hides anything — because it does hide
// something, and gating every planned upgrade would put the most routine act
// in the review queue.
func TestACommitmentIsGatedAgainstTheDeadlineItCovers(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		soon := now.Add(7 * 24 * time.Hour)
		later := now.Add(30 * 24 * time.Hour)

		for _, outcome := range []triage.Outcome{triage.UpgradeNeeded, triage.PatchNeeded} {
			ask := func(committed, binding *time.Time) bool {
				t.Helper()
				needs, err := f.store.NeedsApproval(t.Context(), triage.Proposal{
					Outcome: outcome, CommittedTo: committed, Binding: binding,
				}, 30*24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				return needs
			}

			// Inside the deadline the work already has: ordinary triage.
			if ask(&soon, &later) {
				t.Errorf("%s inside its deadline was gated", outcome)
			}
			// On it exactly is still inside it.
			if ask(&soon, &soon) {
				t.Errorf("%s landing on its deadline was gated", outcome)
			}
			// Past it, the promise defers the worst thing it covers.
			if !ask(&later, &soon) {
				t.Errorf("%s past its deadline was not gated", outcome)
			}
			// A commitment with no date is not a commitment.
			if !ask(nil, &soon) {
				t.Errorf("%s with no date was not gated", outcome)
			}
			// Nothing it covers has a deadline, so there is no date the
			// promise can be inside: the exemption has nothing to measure
			// against and a second person agrees.
			if !ask(&later, nil) {
				t.Errorf("%s covering work with no deadline was not gated", outcome)
			}
		}
	})
}

// The two outcomes hide risk, like every outcome but "affected" — what
// differs is where the gate sits, not whether there is one.
func TestACommitmentHidesRiskAndSaysSo(t *testing.T) {
	for _, outcome := range []triage.Outcome{triage.UpgradeNeeded, triage.PatchNeeded} {
		if !outcome.HidesRisk() {
			t.Errorf("%s does not hide risk, so it would never be gated at all", outcome)
		}
		if !outcome.Commits() {
			t.Errorf("%s does not read as a commitment", outcome)
		}
		if !outcome.Valid() {
			t.Errorf("%s is not a recognized outcome", outcome)
		}
	}
	// And the ones that are not commitments do not claim to be.
	for _, outcome := range []triage.Outcome{
		triage.Affected, triage.NotApplicable, triage.Deferred,
		triage.WontFix, triage.AlreadyFixed,
	} {
		if outcome.Commits() {
			t.Errorf("%s reads as a commitment", outcome)
		}
	}
}

// The commitment is stored with the claim, so a report asking what is promised
// and overdue does not have to know which outcome a date belongs to.
func TestACommitmentIsStoredWithTheClaim(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		by := time.Now().UTC().Add(14 * 24 * time.Hour).Truncate(time.Second)
		made, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
			Place:       f.at(),
			Outcome:     triage.UpgradeNeeded,
			CommittedTo: &by,
			UpgradeTo:   "3.5.2",
			Reasoning:   "Moving the whole package rather than answering each of these.",
			By:          f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		if made.Claim.CommittedTo == nil {
			t.Fatal("the date the work was promised for was not kept")
		}
		if !made.Claim.CommittedTo.Equal(by) {
			t.Errorf("committed to %v, want %v", made.Claim.CommittedTo, by)
		}
		if made.Claim.UpgradeTo == nil || *made.Claim.UpgradeTo != "3.5.2" {
			t.Errorf("the version it moves to is %v", made.Claim.UpgradeTo)
		}

		// And read back the same way, since a claim is read far more often
		// than it is written.
		_ = made
	})
}
