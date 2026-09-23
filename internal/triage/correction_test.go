// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// wholeRecord is the audit window with no ends on it, so a test asking what
// stands is asking about every judgment rather than about a period.
var wholeRecord = [2]time.Time{}

// corrects claims that the scanner matched something that is not here.
func (f *fixture) corrects(t *testing.T, at triage.Place,
	because triage.Justification) (*triage.Decision, error) {

	t.Helper()
	return f.store.Propose(t.Context(), f.triager, triage.Proposal{
		Place: at, Outcome: triage.Mismatched, Justification: because,
		Reasoning: "The advisory is about the upstream project, and this package is " +
			"a different library with a similar name.",
		By: f.proposer,
	})
}

func TestACorrectionSurvivesEveryVersionTheCodeMovesThrough(t *testing.T) {
	// A decision is stored under the versions it was a claim about and stops
	// applying when they move. A claim that the match itself is wrong is not
	// a claim about a version, and a bump does not make a wrong match right —
	// so it stands while a judgment about risk beside it lapses.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		release := f.build(t, f.product, "2026.03")
		old := f.component(t, "libfoo", "1.2.3")
		bumped := f.component(t, "libfoo", "1.2.4")
		found := f.finds(t, release, old, "place-of-libfoo", access.Public)

		at := f.at()
		at.PlaceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		corrected, err := f.corrects(t, at, triage.ComponentNotPresent)
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, corrected.ClaimID, ""); err != nil {
			t.Fatal(err)
		}

		// A judgment about risk at another place in the same build, which is
		// the control: the sweep does reach this product, and what it does to
		// an ordinary claim is what it must not do to a correction.
		beside := f.at()
		beside.PlaceIdentity = "place-of-libbar"
		beside.ConsumerUpstream = ""
		oldBar := f.component(t, "libbar", "1.2.3")
		bar := f.finds(t, release, oldBar, "place-of-libbar", access.Public)
		ordinary := f.agreed(t, beside)

		// The build moves both packages on.
		f.moves(t, release, found, bumped, "place-of-libfoo")
		f.moves(t, release, bar, f.component(t, "libbar", "1.2.4"), "place-of-libbar")
		if _, err := f.store.Lapse(ctx, release.target); err != nil {
			t.Fatal(err)
		}

		if state := f.stateOf(t, ordinary.ID); state != triage.LapsedState {
			t.Errorf("a judgment about risk is %s after the code moved, want it lapsed", state)
		}
		if state := f.stateOf(t, corrected.ID); state != triage.Approved {
			t.Errorf("the correction is %s after a version bump", state)
		}

		// And it still answers for the place, at the version the place now
		// holds — which is what a finding asks when it looks for what stands.
		moved := at
		moved.ComponentUpstream = "1.2.4"
		standing, err := f.store.Applying(ctx, moved)
		if err != nil {
			t.Fatal(err)
		}
		if standing == nil || standing.ID != corrected.ID {
			t.Errorf("nothing stands at the bumped version, want the correction %d", corrected.ID)
		}
	})
}

func TestACorrectionNeedsASecondPerson(t *testing.T) {
	// A dismissal hides risk until the next bump. A correction hides it with
	// nothing scheduled to look again, so the control the second person is
	// there for applies here more rather than less.
	each(t, func(t *testing.T, f *fixture) {
		at := f.at()
		corrected, err := f.corrects(t, at, triage.CodeNotPresent)
		if err != nil {
			t.Fatal(err)
		}
		if !corrected.NeedsApproval {
			t.Fatal("a correction was recorded as standing on one person's say-so")
		}
		if corrected.State != triage.Proposed {
			t.Errorf("a correction nobody has agreed to is %q", corrected.State)
		}
		// And it suppresses nothing until somebody does agree.
		standing, err := f.store.Applying(t.Context(), at)
		if err != nil {
			t.Fatal(err)
		}
		if standing != nil && standing.State == triage.Approved {
			t.Error("a correction waiting for a second person is already in force")
		}
	})
}

func TestACorrectionStatesAReasonNoVersionBumpCanAnswer(t *testing.T) {
	// The two reasons that say something is not there are reasons a bump
	// cannot address. The three that say how the code is reached, or what
	// already stops it, describe surroundings and configuration — a bump
	// changes both, and one of those carried past every bump would be a
	// judgment about risk that nothing re-examines.
	each(t, func(t *testing.T, f *fixture) {
		for _, refused := range []triage.Justification{
			triage.CodeNotInExecutePath,
			triage.CodeNotReachableByAdversary,
			triage.MitigationsExist,
		} {
			at := f.at()
			at.PlaceIdentity = "place-of-" + string(refused)
			// The mitigation, so that the reason this one is refused is the
			// rule under test rather than the rule beside it: a claim that
			// something already stops it has to say what, and left empty it
			// would be turned away before this rule was reached.
			mitigation := ""
			if refused == triage.MitigationsExist {
				mitigation = "The service is not exposed outside the management network."
			}
			if _, err := f.store.Propose(t.Context(), f.triager, triage.Proposal{
				Place: at, Outcome: triage.Mismatched, Justification: refused,
				Mitigation: mitigation,
				Reasoning:  "Recorded as a correction rather than as a dismissal.",
				By:         f.proposer,
			}); err == nil {
				t.Errorf("%q was accepted as the reason a match is wrong", refused)
			}
		}
		for _, taken := range triage.JustificationsCorrecting() {
			at := f.at()
			at.PlaceIdentity = "place-taking-" + string(taken)
			if _, err := f.corrects(t, at, taken); err != nil {
				t.Errorf("%q was refused as the reason a match is wrong: %v", taken, err)
			}
		}
		// And no reason at all is refused, like the outcome beside it whose
		// claim is which reason applies.
		at := f.at()
		at.PlaceIdentity = "place-with-no-reason"
		if _, err := f.corrects(t, at, ""); err == nil {
			t.Error("a correction was recorded with no reason")
		}
	})
}

func TestTheStandingCorrectionsAreReadFromTheRecord(t *testing.T) {
	// Nothing expires a correction, so nothing brings one back round to
	// anybody. The only way to read the set in force is to ask for it, and
	// the record answers with what each is about, who proposed it and who
	// agreed — narrowed by what the reader may see, like everything else.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.at()
		corrected, err := f.corrects(t, at, triage.ComponentNotPresent)
		if err != nil {
			t.Fatal(err)
		}
		// Waiting for a second person is not in force.
		waiting, _, err := f.store.Audit(ctx, f.triager, triage.Filter{
			Outcomes: []triage.Outcome{triage.Mismatched}, InForce: true,
		}, wholeRecord[0], wholeRecord[1], 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 0 {
			t.Fatalf("a correction nobody agreed to reads as standing: %+v", waiting)
		}

		if err := agreeTo(ctx, f.store, f.reviewer, corrected.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		rows, total, err := f.store.Audit(ctx, f.triager, triage.Filter{
			Outcomes: []triage.Outcome{triage.Mismatched}, InForce: true,
		}, wholeRecord[0], wholeRecord[1], 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(rows) != 1 {
			t.Fatalf("the standing set holds %d rows and reports %d", len(rows), total)
		}
		row := rows[0]
		if !row.Standing() {
			t.Error("a correction in force does not read as standing")
		}
		if row.ProposedByName == "" || !row.BySomebodyElse() {
			t.Errorf("the row does not say who claimed it and who agreed: %+v", row)
		}
		if row.Claim == nil || row.Claim.Justification == nil ||
			*row.Claim.Justification != string(triage.ComponentNotPresent) {
			t.Errorf("the row does not say on what grounds: %+v", row.Claim)
		}
		if strings.TrimSpace(row.Reasoning) == "" {
			t.Error("the row carries no reasoning")
		}

		// Somebody who may read the product but not argue about it still sees
		// it; somebody who may see nothing of the product sees none of it.
		theirs, _, err := f.store.Audit(ctx, f.onlooker, triage.Filter{
			Outcomes: []triage.Outcome{triage.Mismatched}, InForce: true,
		}, wholeRecord[0], wholeRecord[1], 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(theirs) != 1 {
			t.Errorf("somebody who may read the product sees %d standing corrections", len(theirs))
		}
		stranger, _, err := f.store.Audit(ctx, access.Subject{Kind: access.Person, ID: -1},
			triage.Filter{Outcomes: []triage.Outcome{triage.Mismatched}, InForce: true},
			wholeRecord[0], wholeRecord[1], 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(stranger) != 0 {
			t.Errorf("somebody granted nothing reads %d standing corrections", len(stranger))
		}
	})
}

func TestACorrectionAnswersForThePlaceAJudgmentAboutRiskWasMadeAt(t *testing.T) {
	// Both can be live at one place: a claim keyed on the versions it was made
	// about, and a claim that the match is wrong keyed on the place. What
	// answers the finding is the correction, because a judgment about risk at
	// a place the match does not describe is a judgment about something that
	// is not there.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.at()
		// The correction first, so the dismissal is the newer row. What
		// decides between them at a place is then the ordering this test is
		// named for and nothing else: the tie-break beside it is newest
		// first, and it would answer with the dismissal.
		corrected, err := f.corrects(t, at, triage.ComponentNotPresent)
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, corrected.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		dismissed := f.agreed(t, at)
		if dismissed.ID <= corrected.ID {
			t.Fatalf("the dismissal is row %d and the correction %d, so the newest-first "+
				"tie-break would pick the correction and this checks nothing",
				dismissed.ID, corrected.ID)
		}
		if state := f.stateOf(t, dismissed.ID); state != triage.Approved {
			t.Errorf("the later judgment is %q, want it standing", state)
		}

		standing, err := f.store.Applying(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		if standing == nil || standing.ID != corrected.ID {
			t.Errorf("the place is answered by %+v, want the correction %d", standing, corrected.ID)
		}
	})
}

func TestWithdrawingIsWhatEndsACorrection(t *testing.T) {
	// Nothing else does. A withdrawal is the one thing that takes a claim
	// about identity back, which is why the standing set has to be readable.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		at := f.at()
		corrected, err := f.corrects(t, at, triage.CodeNotPresent)
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, corrected.ClaimID, ""); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Withdraw(ctx, f.triager, corrected.ClaimID); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, corrected.ID); state != triage.Withdrawn {
			t.Errorf("the correction is %q after being withdrawn", state)
		}
		standing, err := f.store.Applying(ctx, at)
		if err != nil {
			t.Fatal(err)
		}
		if standing != nil {
			t.Error("a withdrawn correction still stands at the place")
		}
		// And the place is free again, which is what a released key is for.
		if _, err := f.corrects(t, at, triage.ComponentNotPresent); err != nil {
			t.Errorf("a place a withdrawn correction used to cover refuses a fresh one: %v", err)
		}
	})
}
