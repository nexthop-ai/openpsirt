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

// openAt opens the fixture's issue at an occurrence in a build of the fixture's
// product, and answers with the occurrence a decision covering it is made at.
func (f *fixture) openAt(t *testing.T, identity string) triage.Occurrence {
	t.Helper()
	in := f.build(t, f.product, "rated-"+identity)
	f.finds(t, in, f.component(t, "lib-"+identity, "1.2.3"), identity, access.Public)
	at := f.at()
	at.OccurrenceIdentity = identity
	at.ConsumerUpstream = ""
	return at
}

// rateIssue sets the published score of the fixture's issue.
func (f *fixture) rateIssue(t *testing.T, centi int) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Table("vulnerability").
		Set(`"score_centi" = ?`, centi).
		Where(`"id" = ?`, f.issue).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestARiseWithinABandLapsesNothing(t *testing.T) {
	// A rescoring inside a band is the same decision about the same issue.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.openAt(t, "band"), 710)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.DecisionID, ""); err != nil {
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

func TestARiseIntoAHigherBandLapsesAgreedAndProposedDecisions(t *testing.T) {
	// Proposed as well as approved: agreed to afterwards, a decision made against
	// the lower rating would stand on a baseline that is already wrong.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.openAt(t, "agreed"), 710)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.DecisionID, ""); err != nil {
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
				t.Errorf("the %s decision is %q after high became critical", name, state)
			}
		}
		if len(lapsed.Told) != 1 || !lapsed.Told[0].RatedWorse || lapsed.Told[0].Rows != 2 {
			t.Errorf("told %+v, want the proposer once about both rows, as rated worse", lapsed.Told)
		}
	})
}

func TestADecisionAboutAnUnratedIssueIsMeasuredFromMedium(t *testing.T) {
	// Unknown is not harmless, and not the lowest either: the way a deadline
	// reads an unrated issue.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.rateIssue(t, 0)
		agreed := f.judged(t, f.openAt(t, "unrated"), 0)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 500)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, agreed.ID); state != triage.Approved {
			t.Errorf("rating an unrated issue medium left the decision %q", state)
		}
		f.rateIssue(t, 750)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, agreed.ID); state != triage.LapsedState {
			t.Errorf("rating an unrated issue high left the decision %q", state)
		}
	})
}

func TestARiseLeavesADecisionItDoesNotBearOn(t *testing.T) {
	// Absent code is not dangerous at any severity.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		absent, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.openAt(t, "absent"), Outcome: triage.NotApplicable,
			Justification: triage.CodeNotPresent,
			Reasoning:     "The driver is not built.", By: f.proposer,
			SeverityCenti: 300, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, absent.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, absent.ID); state != triage.Approved {
			t.Errorf("a decision that the code is absent is %q after low became critical", state)
		}
	})
}

func TestARiseInAnotherProductLapsesNothingHere(t *testing.T) {
	// Narrowed to one product, the sweep leaves another's decisions alone.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.openAt(t, "elsewhere"), 300)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{
			ProductID: f.product + 1000,
		}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, agreed.ID); state != triage.Approved {
			t.Errorf("a sweep of another product left this decision %q", state)
		}
	})
}

func TestARiseLapsesNothingThatCoversNothingOpen(t *testing.T) {
	// A decision covering nothing is not one anybody relies on. Lapsed for a
	// rating, its proposer would be told the finding is open again when none
	// is, and re-affirming it would find nothing to re-make.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.judged(t, f.at(), 300)
		if err := agreeTo(ctx, f.store, f.reviewer, agreed.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, agreed.ID); state != triage.Approved {
			t.Errorf("a decision covering nothing open is %q after it was rated worse", state)
		}
	})
}

func TestARiseLeavesADecisionThatHidesNothingOrIsAboutIdentity(t *testing.T) {
	// "This affects us" is only strengthened by a rise, and a wrong match is
	// not a decision about risk.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		var made []*triage.DecisionOccurrence
		for identity, outcome := range map[string]triage.Outcome{
			"affected": triage.Affected, "mismatched": triage.Mismatched,
		} {
			p := triage.Proposal{
				Occurrence: f.openAt(t, identity), Outcome: outcome,
				Reasoning: "Judged at the old rating.", By: f.proposer,
				SeverityCenti: 300, NeedsApproval: true,
			}
			if outcome == triage.Mismatched {
				p.Justification = triage.ComponentNotPresent
			}
			occurrence, err := f.store.Propose(ctx, f.triager, p)
			if err != nil {
				t.Fatalf("%s: %v", identity, err)
			}
			if err := agreeTo(ctx, f.store, f.reviewer, occurrence.DecisionID, ""); err != nil {
				t.Fatalf("%s: %v", identity, err)
			}
			made = append(made, occurrence)
		}
		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{}); err != nil {
			t.Fatal(err)
		}
		for _, occurrence := range made {
			if state := f.stateOf(t, occurrence.ID); state == triage.LapsedState {
				t.Errorf("decision occurrence %d lapsed after a rise, and the rise bears on nothing it says",
					occurrence.ID)
			}
		}
	})
}

func TestAScanOfOneProductLapsesADecisionInAnother(t *testing.T) {
	// An issue is one row for the deployment. A build in one product raising
	// its rating outgrows a decision another product made about it, so the sweep
	// after a scan asks about the issues the build has open in any product.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other := f.secondProduct(t)
		there := f.build(t, other, "theirs-1")
		f.finds(t, there, f.component(t, "lib-theirs", "1.2.3"), "place-theirs", access.Public)
		who := f.holding(t, "their-triager", map[int64][]access.Role{other: {access.PublicTriage}})
		at := f.at()
		at.ProductID, at.OccurrenceIdentity, at.ConsumerUpstream = other, "place-theirs", ""
		theirs, err := f.store.Propose(ctx, who, triage.Proposal{
			Occurrence: at, Outcome: triage.NotApplicable,
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
			t.Errorf("a decision in another product is %q after a scan here rated its issue worse", state)
		}
	})
}

func TestASiblingDecisionAtAnotherVersionReplacesNothing(t *testing.T) {
	// Two streams at two versions hold sibling decisions at one occurrence, keyed
	// apart by the versions. One lapsing leaves it the proposer's to
	// re-affirm, whichever was made later.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		old := f.build(t, f.product, "sibling-old")
		f.finds(t, old, f.component(t, "lib-sibling", "1.2.3"), "place-sibling", access.Public)
		current := f.build(t, f.product, "sibling-new")
		f.finds(t, current, f.component(t, "lib-sibling-next", "1.2.4"), "place-sibling", access.Public)

		at := f.at()
		at.OccurrenceIdentity, at.ConsumerUpstream = "place-sibling", ""
		first := f.judged(t, at, 300)
		at.ComponentUpstream = "1.2.4"
		second := f.judged(t, at, 300)
		if second.ID < first.ID {
			t.Fatal("the sibling was not written after the decision it stands beside")
		}
		if _, err := f.db.DB.NewUpdate().Table("decision_occurrence").
			Set(`"state" = ?`, triage.LapsedState).Set(`"ended_at" = ?`, time.Now().UTC()).
			Set(`"live_key" = NULL`).Where(`"id" = ?`, first.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		listed, total, err := f.store.ToReaffirm(ctx, f.triager, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(listed) != 1 || listed[0].Decision.ID != first.DecisionID {
			t.Errorf("listed %d of %d, want the lapsed decision beside its standing sibling",
				len(listed), total)
		}
	})
}

// holdUnder moves a finding to another issue.
func (f *fixture) holdUnder(t *testing.T, findingID, issue int64) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Table("finding").Set(`"vulnerability_id" = ?`, issue).
		Where(`"id" = ?`, findingID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestARiseLapsesADecisionUnderAMergedNameAtTheFindingsOfTheIssueItIsReadAs(t *testing.T) {
	// A decision stays filed under the name it was made against when that name
	// merges into another, and the findings it covers are then held under
	// the other. A decision at an occurrence whose finding moved to an unrelated issue
	// covers nothing, however the names line up.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		filed := f.secondIssue(t)
		unrelated, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{
			{Identifier: "CVE-2026-3", Severity: "low"},
		})
		if err != nil {
			t.Fatal(err)
		}
		in := f.build(t, f.product, "rated-merged")
		decisions := map[string]int64{}
		held := map[string]int64{}
		for _, occurrence := range []string{"merged", "moved-away"} {
			row := f.finds(t, in, f.component(t, "lib-"+occurrence, "1.2.3"), occurrence, access.Public)
			f.holdUnder(t, row, filed)
			at := f.at()
			at.VulnerabilityID, at.OccurrenceIdentity, at.ConsumerUpstream = filed, occurrence, ""
			judged := f.judged(t, at, 300)
			if err := agreeTo(ctx, f.store, f.reviewer, judged.DecisionID, ""); err != nil {
				t.Fatal(err)
			}
			decisions[occurrence], held[occurrence] = judged.ID, row
		}
		// The name merges into the fixture's issue, which now holds the
		// finding at the first occurrence. The second occurrence's finding is another
		// issue's.
		if _, err := f.db.DB.NewUpdate().Table("vulnerability").Set(`"issue_id" = ?`, f.issue).
			Where(`"id" = ?`, filed).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.holdUnder(t, held["merged"], f.issue)
		f.holdUnder(t, held["moved-away"], unrelated["CVE-2026-3"])

		f.rateIssue(t, 980)
		if _, err := f.store.LapseRatedWorse(ctx, triage.RatedWorseWhere{OpenIn: in.target}); err != nil {
			t.Fatal(err)
		}
		if state := f.stateOf(t, decisions["merged"]); state != triage.LapsedState {
			t.Errorf("a decision under the merged name is %q after the issue it is read as was rated worse",
				state)
		}
		if state := f.stateOf(t, decisions["moved-away"]); state != triage.Approved {
			t.Errorf("a decision whose finding is another issue's is %q after a rise, and it covers nothing",
				state)
		}
	})
}
