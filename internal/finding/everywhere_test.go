// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// One issue, everywhere it sits — and the total beside it.
//
// The page and the number over it are two queries, which is where they drift:
// the list grouped on a component's name and the total counted components, so
// a build shipping two versions of one name was one row and two in the count.
// Watched failing by grouping on the name again.
func TestTwoVersionsOfAComponentAreTwoSightingsAndAreCountedAsTwo(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// One build that ships two versions of the same library, which is
		// ordinary: two consumers vendored different releases of it.
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, teamd, libnl, libnlNew},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss},
				{Parent: root, Child: teamd},
				{Parent: swss, Child: libnl},
				{Parent: teamd, Child: libnlNew},
			},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-1", libnlNew),
		}); err != nil {
			t.Fatal(err)
		}

		subject := f.holding(t, access.PublicRead)
		rows, total, _, err := f.store.Everywhere(t.Context(), subject,
			f.issueID(t, "CVE-2026-1"), 50)
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("listed %d sightings and counted %d, wanted two of each — "+
				"two versions of a name are two pieces of work", len(rows), total)
		}
		// And each row says which version it is about, rather than one row
		// naming the lower of the two and hiding the other.
		versions := map[string]bool{}
		for _, row := range rows {
			if row.Component != libnl.Name {
				t.Errorf("a component nobody asked about appeared: %s", row.Component)
			}
			versions[row.Version] = true
		}
		if !versions[libnl.Version] || !versions[libnlNew.Version] {
			t.Errorf("the versions listed are %v, wanted %s and %s",
				versions, libnl.Version, libnlNew.Version)
		}
	})
}

func TestTheProductsCarryingAnIssueAreCountedPastThePage(t *testing.T) {
	// A page cut short still says how many products carry the issue, and a
	// product the reader may not see is not one of them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		reported := []finding.Reported{found("CVE-2026-1", libnl)}
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		var others []int64
		for _, name := range []string{"hedgehog", "otter"} {
			elsewhere := f.inAnotherProduct(t, name)
			f.shippedTo(t, elsewhere, twoConsumers())
			if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere), reported); err != nil {
				t.Fatal(err)
			}
			others = append(others, f.productOf(t, elsewhere))
		}
		who := f.holdingIn(t, []int64{f.productID, others[0]}, access.PublicRead)
		rows, total, products, err := f.store.Everywhere(ctx, who, f.issueID(t, "CVE-2026-1"), 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || total != 2 {
			t.Fatalf("listed %d of %d, want one of two, so this proves nothing", len(rows), total)
		}
		if products != 2 {
			t.Errorf("an issue in two readable products of three counts %d products, want 2", products)
		}
	})
}
