// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// Branches and variants named by identifier in one read are the rows each
// identifier names, and an identifier naming nothing is absent.
func TestStreamsAndVariantsReadByIdentifierAreTheRowsTheyName(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		names := catalog.NewStore(db.DB)
		product, err := names.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		master, err := names.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		release, err := names.DeclareStream(ctx, product.ID, "202505", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		broadcom, err := names.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}

		streams, err := names.StreamsByID(ctx, []int64{master.ID, release.ID, -1})
		if err != nil {
			t.Fatal(err)
		}
		if len(streams) != 2 || streams[master.ID].Name != "master" || streams[release.ID].Name != "202505" {
			t.Errorf("read the branches as %+v", streams)
		}
		variants, err := names.VariantsByID(ctx, []int64{broadcom.ID, -1})
		if err != nil {
			t.Fatal(err)
		}
		if len(variants) != 1 || variants[broadcom.ID].Name != "broadcom" {
			t.Errorf("read the variants as %+v", variants)
		}
		none, err := names.StreamsByID(ctx, nil)
		if err != nil || len(none) != 0 {
			t.Errorf("no identifiers read %+v, %v", none, err)
		}
	})
}
