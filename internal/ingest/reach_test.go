// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// A scan in a product somebody cannot see answers as a scan that does not
// exist, for a person holding nothing on the product and for a pipeline
// credential scoped to another one.
//
// Verified by deleting the `!subject.Sees(productID)` refusal in Of: both
// subjects then read the scan.
func TestAScanInAnUnseenProductAnswersAsNoScan(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		other, err := cat.DeclareProduct(ctx, "onie", "Open Network Install Environment")
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
		s := ingest.NewStore(db.DB)
		scan, _, err := s.Record(ctx, arriving(target.ID, "held", time.Now().UTC().Add(-time.Hour)))
		if err != nil {
			t.Fatal(err)
		}

		reader := access.NewPerson(1, "reader", false,
			map[int64][]access.Role{product.ID: {access.PublicRead}}, 0)
		if _, err := s.Of(ctx, reader, target.ID, scan.ID); err != nil {
			t.Fatalf("somebody who reads the product could not read its scan: %v", err)
		}

		for name, subject := range map[string]access.Subject{
			"a person holding nothing on the product": access.NewPerson(2, "stranger", false,
				map[int64][]access.Role{other.ID: {access.PublicRead}}, 0),
			"a pipeline scoped to another product": access.NewPipeline(3, "key-1",
				access.Scope{ProductID: other.ID}),
		} {
			if got, err := s.Of(ctx, subject, target.ID, scan.ID); !errors.Is(err, ingest.ErrNoScan) {
				t.Errorf("%s got %+v and %v, want no scan", name, got, err)
			}
		}
	})
}
