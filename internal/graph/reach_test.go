// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// The way down to a component is refused to somebody who may not know the
// build exists, and given to a collaborator brought into one case on the
// product, whose issue sits at a component the way leads to.
//
// Verified by deleting the refusal in knowsBuild: the stranger is then given
// the way down.
func TestAWayDownIsRefusedToSomebodyWhoHoldsNothingOnTheProduct(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), tree()); err != nil {
			t.Fatal(err)
		}
		curl, err := f.store.ComponentAt(ctx, f.targetID, "curl")
		if err != nil {
			t.Fatal(err)
		}
		product := *f.scope.ProductID

		stranger := access.NewPerson(2, "stranger", false, nil, 0)
		if chains, err := f.store.Chains(ctx, stranger, f.targetID, []int64{curl}); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody holding nothing on the product got %v and %v, want a refusal", chains, err)
		}

		collaborator := access.NewPerson(3, "collaborator", false, nil, 0).
			OnCases(map[int64][]int64{product: {1}})
		chains, err := f.store.Chains(ctx, collaborator, f.targetID, []int64{curl})
		if err != nil {
			t.Fatalf("a case collaborator was refused the way down: %v", err)
		}
		if got := chain(chains[curl]); got != "sonic > curl" {
			t.Errorf("a case collaborator was given %q", got)
		}
	})
}
