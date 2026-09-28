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

// A commitment a claim argued for is moved only by that claim. A second claim
// promising a different version for the same package in the same build is
// refused, naming the claim that stands, and the standing commitment is left
// as it was; the claim that made it may still revise it.
//
// Verified by deleting the second-claim refusal in movedTo: the second claim
// then rewrites the version and takes over the commitment.
func TestASecondClaimDoesNotMoveACommitmentAnotherClaimMade(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		component, err := f.graph.ComponentAs(ctx, f.target, "libnl-3-200", graph.Choice{})
		if err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PublicTriage)
		commit := func(to string, claim int64) error {
			_, err := f.store.CommitWithin(ctx, f.db.DB, who, f.productID, component,
				to, nil, &claim, []int64{f.target}, nil)
			return err
		}
		standing := func() finding.Upgrade {
			var row finding.Upgrade
			if err := f.db.DB.NewSelect().Model(&row).
				Where("target_id = ?", f.target).Scan(ctx); err != nil {
				t.Fatal(err)
			}
			return row
		}

		const first, second = int64(101), int64(202)
		if err := commit("3.9.0", first); err != nil {
			t.Fatalf("the first commitment: %v", err)
		}

		err = commit("3.10.0", second)
		if err == nil || !strings.Contains(err.Error(), "under claim 101") {
			t.Errorf("a second claim moving the commitment got %v, want the standing claim named", err)
		}
		if row := standing(); row.ToVersion != "3.9.0" || row.ClaimID == nil || *row.ClaimID != first {
			t.Errorf("after the refusal the commitment is to %s under claim %v, want 3.9.0 under %d",
				row.ToVersion, row.ClaimID, first)
		}

		if err := commit("3.10.0", first); err != nil {
			t.Fatalf("the claim that made the commitment revising it: %v", err)
		}
		if row := standing(); row.ToVersion != "3.10.0" {
			t.Errorf("a revision by the claim that made it left the version at %s", row.ToVersion)
		}
	})
}
