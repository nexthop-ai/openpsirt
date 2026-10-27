// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// builds is the targets a decision records it was made on, read from the table.
func (f *fixture) builds(t *testing.T, decision int64) []int64 {
	t.Helper()
	var targets []int64
	if err := f.db.DB.NewRaw(`SELECT "target_id" FROM "decision_build" WHERE "decision_id" = ?`,
		decision).Scan(t.Context(), &targets); err != nil {
		t.Fatal(err)
	}
	slices.Sort(targets)
	return targets
}

func TestTheRowsHeldBackFromADecisionKeepTheBuildsItWasMadeOn(t *testing.T) {
	// Holding rows back writes a decision of its own with the same argument, so
	// it was made on the same builds. Recorded as none, an advisory would say
	// nothing about where a decision it states was made.
	//
	// On every engine, because what this pins is rows a write leaves.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		var target int64
		if err := f.db.DB.NewRaw(`SELECT MIN("id") FROM "target"`).Scan(ctx, &target); err != nil {
			t.Fatal(err)
		}
		occurrences := f.occurrences("under-a", "under-b")
		proposals := make([]triage.Proposal, 0, len(occurrences))
		for _, at := range occurrences {
			proposals = append(proposals, triage.Proposal{
				Occurrence: at, Outcome: triage.NotApplicable,
				Justification: triage.CodeNotInExecutePath,
				Reasoning:     "The parser is never reached: we only call the encoder.",
				By:            f.proposer, NeedsApproval: true,
				MadeOn: []int64{target, target},
			})
		}
		recorded, err := f.store.ProposeMany(ctx, f.triager, proposals)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.builds(t, recorded[0].DecisionID); !slices.Equal(got, []int64{target}) {
			t.Fatalf("the decision records %v, want the one build once", got)
		}

		held, err := f.store.Split(ctx, f.triager, recorded[0].DecisionID,
			[]int64{recorded[1].ID}, "This one is reachable from the CLI.")
		if err != nil {
			t.Fatal(err)
		}
		if got := f.builds(t, held.ID); !slices.Equal(got, []int64{target}) {
			t.Errorf("the rows held back record %v, want the build the decision was made on", got)
		}
	})
}
