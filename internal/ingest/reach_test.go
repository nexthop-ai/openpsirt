// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// A scan in a product somebody cannot see answers as a scan that does not
// exist, for a person holding nothing on the product and for a pipeline
// credential scoped to another one.
//
// Verified by deleting the `!subject.Sees(productID)` refusal in Of: both
// subjects then read the scan.
func TestAScanInAnUnseenProductAnswersAsNoScan(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		db := w.DB
		product, build := w.Product, w.Build
		other := w.DeclareProduct("onie", "Open Network Install Environment")
		s := ingest.NewStore(db.DB)
		scan, _, err := s.Record(ctx, arriving(build.ID, "held", time.Now().UTC().Add(-time.Hour)))
		if err != nil {
			t.Fatal(err)
		}

		reader := access.NewPerson(1, "reader", false,
			map[int64][]access.Role{product.ID: {access.PublicRead}}, 0)
		if _, err := s.Of(ctx, reader, build.ID, scan.ID); err != nil {
			t.Fatalf("somebody who reads the product could not read its scan: %v", err)
		}

		for name, subject := range map[string]access.Subject{
			"a person holding nothing on the product": access.NewPerson(2, "stranger", false,
				map[int64][]access.Role{other.ID: {access.PublicRead}}, 0),
			"a pipeline scoped to another product": access.NewPipeline(3, "key-1",
				access.Scope{ProductID: other.ID}),
		} {
			if got, err := s.Of(ctx, subject, build.ID, scan.ID); !errors.Is(err, ingest.ErrNoScan) {
				t.Errorf("%s got %+v and %v, want no scan", name, got, err)
			}
		}
	})
}

// The last upload turned away from a build is a receipt, read by the rule
// the receipts hold: a person holding nothing on the product and a pipeline
// scoped to another product are refused it, and a reader of the product
// reads it.
func TestTheLastRefusalOfABuildInAnUnseenProductIsRefused(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		product, build := w.Product, w.Build
		other := w.DeclareProduct("onie", "Open Network Install Environment")
		s := ingest.NewStore(w.DB.DB)
		uploader := access.NewPipeline(4, "key-2", access.Scope{ProductID: product.ID})
		if err := s.Refused(ctx, uploader, ingest.Refusal{BuildID: build.ID, Reason: "not an inventory"}); err != nil {
			t.Fatal(err)
		}

		reader := access.NewPerson(1, "reader", false,
			map[int64][]access.Role{product.ID: {access.PublicRead}}, 0)
		if got, err := s.LastRefusal(ctx, reader, build.ID); err != nil || got == nil || got.Reason != "not an inventory" {
			t.Fatalf("somebody who reads the product read %+v (%v), want the refusal", got, err)
		}
		for name, subject := range map[string]access.Subject{
			"a person holding nothing on the product": access.NewPerson(2, "stranger", false,
				map[int64][]access.Role{other.ID: {access.PublicRead}}, 0),
			"a pipeline scoped to another product": access.NewPipeline(3, "key-1",
				access.Scope{ProductID: other.ID}),
		} {
			if got, err := s.LastRefusal(ctx, subject, build.ID); !errors.Is(err, access.ErrDenied) || got != nil {
				t.Errorf("%s got %+v and %v, want a denial", name, got, err)
			}
		}
	})
}
