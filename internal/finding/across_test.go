// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// through is one issue in one component, pulled in by a consumer so the way
// down has something in it worth naming.
func through(library graph.Described) graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{swss, library},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss},
			{Parent: swss, Child: library},
		},
	}
}

func TestOneIssueInTwoBuildsIsOneRowAcrossThemAndSaysHowMany(t *testing.T) {
	// The list is not a build's. What the same code in two variants must
	// not do is read as two pieces of work: one item across variants says
	// findings identical across variants are one item, and while the list
	// answered for one build at a time there was nowhere that could be
	// seen.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// The same code, the same version, the same way down, in a second
		// variant of the same product.
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		one, total, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(one) != 1 {
			t.Fatalf("one build reads %d rows of %d, want one", len(one), total)
		}
		if one[0].Places != 1 {
			t.Errorf("one build counts %d places, want the one it holds", one[0].Places)
		}
		// A build's own list draws the way down and says nothing about other
		// builds, because there is nothing to say: the selection is this one.
		if one[0].Parent == "" || one[0].Chains == 0 {
			t.Errorf("a build's own row lost its way down: %+v", one[0])
		}
		if one[0].Builds > 1 || one[0].Stream != "" || one[0].Variant != "" {
			t.Errorf("a build's own row names a build it is already scoped to: %+v", one[0])
		}

		both, total, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(both) != 1 {
			t.Fatalf("the product reads %d rows of %d, want the two builds collapsed to one",
				len(both), total)
		}
		row := both[0]
		if row.Places != 2 {
			t.Errorf("the row counts %d places, want one in each build", row.Places)
		}
		if row.Builds != 2 {
			t.Errorf("the row says %d builds hold it, want 2", row.Builds)
		}
		if row.Stream == "" || row.Variant == "" {
			t.Errorf("the row names no build to link to: %+v", row)
		}
		// The way down is absent rather than taken from the build the row
		// happened to name. Both builds reach it, each its own way, and
		// filling these from one of them presents a route as the answer.
		if row.Owner != "" || row.Parent != "" || row.Middle != 0 || row.Chains != 0 {
			t.Errorf("a row spanning builds drew a way down: %+v", row)
		}
	})
}

func TestAGroupOnlyOneBuildHoldsSaysSoAcrossTheProduct(t *testing.T) {
	// The count is what tells one situation from the other: the same issue
	// everywhere, and the same issue in one variant only, are different pieces
	// of work and the row has to distinguish them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(teamd))
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-2", teamd),
		}); err != nil {
			t.Fatal(err)
		}

		rows, total, err := f.store.Groups(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("the product reads %d rows of %d, want one per build", len(rows), total)
		}
		for _, row := range rows {
			if row.Builds != 1 {
				t.Errorf("%s says %d builds hold it, want the one that does",
					row.Vulnerability, row.Builds)
			}
			if row.Places != 1 {
				t.Errorf("%s counts %d places, want 1", row.Vulnerability, row.Places)
			}
		}
	})
}

func TestASubtreeIsRefusedWhereTheSelectionHoldsMoreThanOneBuild(t *testing.T) {
	// A subtree is a walk over one build's edges. Answered across several it
	// would have walked whichever build the identifier defaulted to — zero —
	// and come back empty, which reads exactly like a subtree with nothing
	// open in it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)
		under := f.componentID(t, swss.Name)

		// It answers for one build.
		rows, _, err := f.store.Groups(ctx, who, f.scope, 50, 0,
			finding.Filter{Beneath: &under})
		if err != nil {
			t.Fatalf("beneath a component in one build: %v", err)
		}
		if len(rows) != 1 {
			t.Errorf("beneath swss in one build reads %d rows, want 1", len(rows))
		}

		// And refuses across several rather than answering emptily.
		if _, _, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0,
			finding.Filter{Beneath: &under}); err == nil {
			t.Error("a subtree across two builds was answered rather than refused")
		}
	})
}

func TestAProductNobodyMayReadAnswersNothingAtEveryScopeLevel(t *testing.T) {
	// Visibility is the data layer's, and widening the selection is
	// exactly the shape that leaves a check behind on the narrow path.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		stranger := access.NewPerson(9, "nobody@example.com", false,
			map[int64][]access.Role{f.productID + 999: {access.PublicRead}}, 0)

		for what, scope := range map[string]finding.Scope{
			"one build":   f.scope,
			"the product": f.wholeProduct(),
		} {
			if _, _, err := f.store.Groups(ctx, stranger, scope, 50, 0, finding.Filter{}); err == nil {
				t.Errorf("somebody holding nothing here read the findings of %s", what)
			}
			if _, _, err := f.store.ComponentGroups(ctx, stranger, scope, 50, 0,
				finding.Filter{}); err == nil {
				t.Errorf("somebody holding nothing here read %s by component", what)
			}
		}
	})
}
