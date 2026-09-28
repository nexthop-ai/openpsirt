// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestManyIssuesAreToldOfAsEachOneWouldBe(t *testing.T) {
	// The list form answers each issue as the single question would: told
	// where a finding of it in this product is one the reader may read, and
	// not where it sits undisclosed or only in another product.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
		}); err != nil {
			t.Fatal(err)
		}
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := catalog.NewStore(f.db.DB).DeclareVariant(ctx, other.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.anotherBranchOf(t, other.ID, "main")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere), []finding.Reported{
			found("CVE-2026-3", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		names := finding.NewVulnerabilities(f.db.DB)
		ids := map[string]int64{}
		for _, name := range []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"} {
			id, err := names.ByName(ctx, name)
			if err != nil {
				t.Fatal(err)
			}
			ids[name] = id
		}
		if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
			Set("visibility = ?", access.Private).
			Where("vulnerability_id = ?", ids["CVE-2026-2"]).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		reader := f.planner(t, access.PublicRead)
		told, err := f.store.ToldOfIn(ctx, reader, f.productID,
			[]int64{ids["CVE-2026-1"], ids["CVE-2026-2"], ids["CVE-2026-3"]})
		if err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]bool{
			"CVE-2026-1": true, "CVE-2026-2": false, "CVE-2026-3": false,
		} {
			if told[ids[name]] != want {
				t.Errorf("%s told of: %v, want %v", name, told[ids[name]], want)
			}
			single, err := f.store.MayBeToldOfIn(ctx, reader, f.productID, ids[name])
			if err != nil {
				t.Fatal(err)
			}
			if single != want {
				t.Errorf("%s asked alone: %v, want %v", name, single, want)
			}
		}
	})
}
