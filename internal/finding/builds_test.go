// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

func TestAPromiseNamesOnlyBuildsOfItsOwnProduct(t *testing.T) {
	// Planning an upgrade names builds by identifier, so a build of another
	// product named beside this one's would write that product's places.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := catalog.NewStore(f.db.DB).DeclareVariant(ctx, other.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.anotherBranchOf(t, other.ID, "main")

		if _, err := f.store.BuildsForWithin(ctx, f.db.DB, f.productID,
			[]int64{f.target, elsewhere}); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a build of another product was accepted beside this one's: %v", err)
		}
		here, err := f.store.BuildsForWithin(ctx, f.db.DB, f.productID, []int64{f.target, f.target})
		if err != nil || len(here) != 1 {
			t.Errorf("this product's build named twice answered %v, %v", here, err)
		}
	})
}
