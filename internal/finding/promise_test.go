// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A commitment a decision argued for is moved only by that decision. A second
// decision promising a different version for the same package in the same build
// is refused, naming the decision that stands, and the standing commitment is
// left as it was; the decision that made it may still revise it.
//
// Verified by deleting the second-decision refusal in movedTo: the second
// decision then rewrites the version and takes over the commitment.
func TestASecondDecisionDoesNotMoveACommitmentAnotherDecisionMade(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		component, err := f.graph.ComponentAs(ctx, f.build, "libnl-3-200", graph.Choice{})
		if err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PublicTriage)
		commit := func(to string, decision int64) error {
			_, err := f.store.CommitWithin(ctx, f.db.DB, who, f.productID, component,
				to, nil, &decision, []int64{f.build}, nil)
			return err
		}
		standing := func() finding.Upgrade {
			var row finding.Upgrade
			if err := f.db.DB.NewSelect().Model(&row).
				Where(`"build_id" = ?`, f.build).Scan(ctx); err != nil {
				t.Fatal(err)
			}
			return row
		}

		const first, second = int64(101), int64(202)
		if err := commit("3.9.0", first); err != nil {
			t.Fatalf("the first commitment: %v", err)
		}

		err = commit("3.10.0", second)
		if err == nil || !strings.Contains(err.Error(), "under decision 101") {
			t.Errorf("a second decision moving the commitment got %v, want the standing decision named", err)
		}
		if row := standing(); row.ToVersion != "3.9.0" || row.DecisionID == nil || *row.DecisionID != first {
			t.Errorf("after the refusal the commitment is to %s under decision %v, want 3.9.0 under %d",
				row.ToVersion, row.DecisionID, first)
		}

		if err := commit("3.10.0", first); err != nil {
			t.Fatalf("the decision that made the commitment revising it: %v", err)
		}
		if row := standing(); row.ToVersion != "3.10.0" {
			t.Errorf("a revision by the decision that made it left the version at %s", row.ToVersion)
		}
	})
}

// A second decision promising a bump of the same package for another build
// leaves the first decision's commitment where it is: only the decision that made
// a commitment withdraws it. The same promise stated again by a second decision
// is refused.
func TestASecondDecisionKeepsTheCommitmentsAnotherDecisionMade(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		component, err := f.graph.ComponentAs(ctx, f.build, "libnl-3-200", graph.Choice{})
		if err != nil {
			t.Fatal(err)
		}
		other := f.anotherBranch(t, "release-2")
		who := f.planner(t, access.PublicTriage)
		commit := func(to string, decision int64, builds ...int64) error {
			_, err := f.store.CommitWithin(ctx, f.db.DB, who, f.productID, component,
				to, nil, &decision, builds, nil)
			return err
		}
		owner := func(build int64) *int64 {
			var rows []finding.Upgrade
			if err := f.db.DB.NewSelect().Model(&rows).
				Where(`"build_id" = ?`, build).Scan(ctx); err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 {
				return nil
			}
			return rows[0].DecisionID
		}

		const first, second = int64(101), int64(202)
		if err := commit("3.9.0", first, f.build); err != nil {
			t.Fatalf("the first commitment: %v", err)
		}
		if err := commit("3.9.0", second, other); err != nil {
			t.Fatalf("the second decision's commitment: %v", err)
		}
		if got := owner(f.build); got == nil || *got != first {
			t.Errorf("the first decision's commitment is now held by %v, want decision %d", got, first)
		}
		if got := owner(other); got == nil || *got != second {
			t.Errorf("the second build's commitment is held by %v, want decision %d", got, second)
		}

		// The same promise stated again by a second decision is refused: its
		// occurrences would rest on a date only the first decision moves.
		if err := commit("3.9.0", second, f.build, other); err == nil {
			t.Error("a second decision restated a commitment another decision made, and was accepted")
		}
		if got := owner(f.build); got == nil || *got != first {
			t.Errorf("restating the promise moved the commitment to %v, want decision %d", got, first)
		}

		// The decision that made a commitment still withdraws it by narrowing.
		third := f.anotherBranch(t, "release-3")
		if err := commit("3.9.0", second, third); err != nil {
			t.Fatal(err)
		}
		if got := owner(other); got != nil {
			t.Errorf("the second decision narrowed its builds and its commitment is held by %v", got)
		}
	})
}
