// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// What a scan's application reports is what was applied, when the commit of a
// first attempt is refused and the whole of it runs again. A count carried over
// from the attempt that rolled back doubles, and the doubled number of
// unexplained closures is what raises the warning that findings disappeared.
func TestAScanAppliedAgainAfterALostCommitCountsOnce(t *testing.T) {
	db, race := dbtest.Racing(t, nil)
	ctx := t.Context()
	cat := catalog.NewStore(db.DB)
	product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
	if err != nil {
		t.Fatal(err)
	}
	variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
	if err != nil {
		t.Fatal(err)
	}
	target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		db: db, store: finding.NewStore(db.DB), graph: graph.NewStore(db.DB),
		target: target.ID, productID: product.ID, scans: ingest.NewStore(db.DB),
		built: time.Now().UTC().Add(-72 * time.Hour),
	}
	f.shipped(t, twoConsumers())
	if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
		found("CVE-2026-1", libnl),
	}); err != nil {
		t.Fatal(err)
	}

	// Reported by nothing, so every place closes with no reason given.
	quiet := f.run(t)
	race.Arm(1)
	applied, err := f.store.Apply(ctx, f.target, quiet, nil)
	if err != nil {
		t.Fatal(err)
	}
	if race.Unspent() != 0 {
		t.Fatal("the application committed nothing, so no attempt was retried and this checks nothing")
	}
	if applied.Closed != 2 || applied.Unexplained != 2 {
		t.Errorf("closed %d, %d of them unexplained; want the 2 places, counted once", applied.Closed, applied.Unexplained)
	}
}
