// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A component row is shared across products and holds what the first one
// stated. A finding shows the name and version its own build stated, so
// another product describing the package first decides nothing it shows.
func TestAFindingShowsTheNameAndVersionItsOwnBuildStated(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		cat := catalog.NewStore(f.db.DB)
		other, err := cat.DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, other.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		poisoned := libnl
		poisoned.Name, poisoned.Version = "nothing", "99.0"
		f.shippedTo(t, f.anotherBranchOf(t, other.ID, "main"), graph.Snapshot{
			Root:         at("edge", "1.0"),
			Components:   []graph.Described{poisoned},
			Dependencies: []graph.Dependency{{Parent: at("edge", "1.0"), Child: poisoned}},
		})

		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) == 0 {
			t.Fatal("the issue opened nowhere")
		}
		who := f.holding(t, access.PublicRead)

		evidence, err := f.store.Detail(ctx, who, f.build, open[0].VulnerabilityID, open[0].ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Component != libnl.Name || evidence.Version != libnl.Version {
			t.Errorf("a finding's evidence shows %s %s, which another product stated",
				evidence.Component, evidence.Version)
		}

		groups, _, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(groups) == 0 {
			t.Fatal("the findings list holds nothing")
		}
		for _, group := range groups {
			if group.Component != libnl.Name || group.Version != libnl.Version {
				t.Errorf("the findings list shows %s %s, which another product stated",
					group.Component, group.Version)
			}
		}

		components, _, err := f.store.ComponentGroups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		for _, group := range components {
			if group.Component != libnl.Name || group.Version != libnl.Version {
				t.Errorf("the list by component shows %s %s, which another product stated",
					group.Component, group.Version)
			}
		}

		// The versions carrying the issue are found by the build's own name for
		// the component, in any capitals, and by the row's.
		for _, typed := range []string{"LIBNL-3-200", "nothing"} {
			choices, err := f.store.VersionsWithIssue(ctx, who, f.build, open[0].VulnerabilityID, typed)
			if err != nil {
				t.Fatal(err)
			}
			if len(choices) != 1 || choices[0].Version != libnl.Version {
				t.Errorf("typed %q, the versions carrying the issue are %+v", typed, choices)
			}
		}

		rows, _, err := f.store.Register(ctx, who, f.build, finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			t.Fatal("the register holds nothing")
		}
		for _, row := range rows {
			if row.Component != libnl.Name || row.Version != libnl.Version {
				t.Errorf("the register shows %s %s, which another product stated", row.Component, row.Version)
			}
		}
	})
}

// A page spanning products names each row as its own build stated it, or as
// the component row where that build states nothing: never as a build of
// another product stated it.
func TestARowAcrossProductsIsNeverNamedByAnotherProductsBuild(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.applied(t, found("CVE-2026-1", libnl))
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		theirs := twoConsumers()
		for i, c := range theirs.Components {
			if c.Purl == libnl.Purl {
				theirs.Components[i].Name, theirs.Components[i].Version = "nothing", "99.0"
			}
		}
		for i, d := range theirs.Dependencies {
			if d.Child.Purl == libnl.Purl {
				theirs.Dependencies[i].Child = theirs.Components[2]
			}
		}
		f.shippedTo(t, elsewhere, theirs)
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere),
			[]finding.Reported{found("CVE-2026-1", theirs.Components[2])}); err != nil {
			t.Fatal(err)
		}
		// The fixture's build as a node written before nodes held a name.
		if _, err := f.db.DB.NewUpdate().TableExpr(`"graph_node"`).
			Set(`"name" = NULL`).Set(`"version" = NULL`).Set(`"name_folded" = NULL`).
			Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		who := f.holdingIn(t, []int64{f.productID, f.productOf(t, elsewhere)}, access.PublicRead)
		across, _, err := f.store.Anywhere(ctx, who, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		shown := map[string]bool{}
		for _, row := range across {
			shown[row.Component+" "+row.Version] = true
		}
		if !shown[libnl.Name+" "+libnl.Version] || !shown["nothing 99.0"] || len(shown) != 2 {
			t.Errorf("across products the rows show %v, want each product's own name", shown)
		}
	})
}
