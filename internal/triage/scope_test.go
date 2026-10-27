// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Whom a statement holds for is decided by the reason where the decision states
// nothing: that the code or the component is absent, and a match that was
// wrong, hold for anybody shipping the component; every other reason, and
// every outcome that is not a dismissal, holds for this build.
func TestTheReasonDecidesWhomAStatementHoldsFor(t *testing.T) {
	for _, tc := range []struct {
		outcome       triage.Outcome
		justification triage.Justification
		want          triage.Scope
	}{
		{triage.NotApplicable, triage.CodeNotPresent, triage.Portable},
		{triage.NotApplicable, triage.ComponentNotPresent, triage.Portable},
		{triage.Mismatched, triage.ComponentNotPresent, triage.Portable},
		{triage.Mismatched, triage.CodeNotPresent, triage.Portable},
		{triage.NotApplicable, triage.CodeNotInExecutePath, triage.BuildSpecific},
		{triage.NotApplicable, triage.CodeNotReachableByAdversary, triage.BuildSpecific},
		{triage.NotApplicable, triage.MitigationsExist, triage.BuildSpecific},
		{triage.AlreadyFixed, "", triage.BuildSpecific},
		{triage.WontFix, "", triage.BuildSpecific},
		{triage.Affected, "", triage.BuildSpecific},
	} {
		if got := triage.ScopeOf(tc.outcome, tc.justification, ""); got != tc.want {
			t.Errorf("%s with %q holds for %q, want %q", tc.outcome, tc.justification, got, tc.want)
		}
		// And a stated scope wins whatever the reason says.
		for _, stated := range triage.Scopes() {
			if got := triage.ScopeOf(tc.outcome, tc.justification, stated); got != stated {
				t.Errorf("%s with %q stated %q holds for %q", tc.outcome, tc.justification, stated, got)
			}
		}
	}
}

// A decision stating whom its statement holds for keeps it, a re-affirmation and
// the rows an approver sets aside carry it, and a scope that is not one, or one
// on a deferral, is refused.
func TestADecisionKeepsWhomItsStatementHoldsFor(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		said := triage.Proposal{
			Occurrence: f.at(), Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath, Scope: triage.Portable,
			Reasoning: "Never reached on any build of this component.", By: f.proposer,
			NeedsApproval: true,
		}
		occurrence, err := f.store.Propose(ctx, f.triager, said)
		if err != nil {
			t.Fatal(err)
		}
		decision := new(triage.Decision)
		if err := f.db.DB.NewSelect().Model(decision).Where(`"id" = ?`, occurrence.DecisionID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if decision.Scope == nil || *decision.Scope != triage.Portable {
			t.Errorf("the decision stores %v, want the scope it stated", decision.Scope)
		}

		another := f.at()
		another.OccurrenceIdentity = "place-two"
		unknown := said
		unknown.Occurrence, unknown.Scope = another, "everybody"
		if _, err := f.store.Propose(ctx, f.triager, unknown); !refusal.In(err) {
			t.Errorf("a scope that is not one was taken: %v", err)
		}
		later := time.Now().UTC().Add(72 * time.Hour).Truncate(24 * time.Hour)
		deferred := triage.Proposal{
			Occurrence: another, Outcome: triage.Deferred, DeferredUntil: &later, Scope: triage.Portable,
			Reasoning: "Next sprint.", By: f.proposer,
		}
		if _, err := f.store.Propose(ctx, f.triager, deferred); !refusal.In(err) {
			t.Errorf("a scope on a deferral was taken: %v", err)
		}
	})
}

// An extension keeps whom the decision it carries holds for: taken where it
// states nothing, and refused where it states something else.
func TestAnExtensionKeepsWhomItsSourceHoldsFor(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		source, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.at(), Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath, Scope: triage.Portable,
			Reasoning: "Never reached.", By: f.proposer, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.ApproveDecision(ctx, f.reviewer, source.DecisionID, "", nil, ""); err != nil {
			t.Fatal(err)
		}
		another := f.at()
		another.VulnerabilityID = f.secondIssue(t)
		carried := triage.Proposal{
			Occurrence: another, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Reasoning:     "Same path as the last one.", By: f.proposer, NeedsApproval: true,
		}
		other := carried
		other.Scope = triage.BuildSpecific
		if _, err := f.store.Extend(ctx, f.triager, source.DecisionID,
			[]triage.Proposal{other}); !errors.Is(err, triage.ErrNotExtendable) {
			t.Errorf("an extension stating another scope was taken: %v", err)
		}
		made, err := f.store.Extend(ctx, f.triager, source.DecisionID, []triage.Proposal{carried})
		if err != nil {
			t.Fatal(err)
		}
		decision := new(triage.Decision)
		if err := f.db.DB.NewSelect().Model(decision).Where(`"id" = ?`, made[0].DecisionID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if decision.Scope == nil || *decision.Scope != triage.Portable {
			t.Errorf("the extension stores %v, want its source's scope", decision.Scope)
		}
	})
}
