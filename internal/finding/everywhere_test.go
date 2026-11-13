// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"slices"
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
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-1", libnlNew),
		}); err != nil {
			t.Fatal(err)
		}

		subject := f.holding(t, access.PublicRead)
		rows, total, _, err := f.store.Everywhere(t.Context(), subject,
			f.issueID(t, "CVE-2026-1"), 0, 50, 0)
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
		if _, err := f.store.Apply(ctx, f.build, f.run(t), reported); err != nil {
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
		rows, total, products, err := f.store.Everywhere(ctx, who, f.issueID(t, "CVE-2026-1"), 0, 1, 0)
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

func TestOneProductNarrowsAnIssuesSightingsAndTheirCounts(t *testing.T) {
	// A product named keeps only its rows, and the total and the count of
	// products describe those rows, so a page holding all of one product's
	// rows is the whole of that product's answer.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		reported := []finding.Reported{found("CVE-2026-1", libnl)}
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.build, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		elsewhere := f.inAnotherProduct(t, "hedgehog")
		f.shippedTo(t, elsewhere, twoConsumers())
		if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere), reported); err != nil {
			t.Fatal(err)
		}
		other := f.productOf(t, elsewhere)
		who := f.holdingIn(t, []int64{f.productID, other}, access.PublicRead)
		issue := f.issueID(t, "CVE-2026-1")
		if _, total, _, err := f.store.Everywhere(ctx, who, issue, 0, 50, 0); err != nil || total != 2 {
			t.Fatalf("counted %d in every product (%v), want 2, so this proves nothing", total, err)
		}
		rows, total, products, err := f.store.Everywhere(ctx, who, issue, other, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || total != 1 || products != 1 {
			t.Fatalf("one product's answer listed %d, counted %d in %d products, want 1, 1 and 1",
				len(rows), total, products)
		}
		if rows[0].Product != "hedgehog" {
			t.Errorf("one product's answer listed %s, want hedgehog", rows[0].Product)
		}
	})
}

func TestAnIssuesSightingsReadAPageAtATimeAreEverySightingOnce(t *testing.T) {
	// The affected-builds editor reads every page of one product's answer and
	// writes the whole set back, so the pages hold every row exactly once.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		reported := []finding.Reported{found("CVE-2026-1", libnl)}
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.build, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		readable := []int64{f.productID}
		for _, name := range []string{"hedgehog", "otter"} {
			elsewhere := f.inAnotherProduct(t, name)
			f.shippedTo(t, elsewhere, twoConsumers())
			if _, err := f.store.Apply(ctx, elsewhere, f.runOn(t, elsewhere), reported); err != nil {
				t.Fatal(err)
			}
			readable = append(readable, f.productOf(t, elsewhere))
		}
		who := f.holdingIn(t, readable, access.PublicRead)
		issue := f.issueID(t, "CVE-2026-1")
		seen := map[string]bool{}
		for offset := 0; ; offset++ {
			rows, total, _, err := f.store.Everywhere(ctx, who, issue, 0, 1, offset)
			if err != nil {
				t.Fatal(err)
			}
			if total != 3 {
				t.Fatalf("counted %d, want 3, so this proves nothing", total)
			}
			if len(rows) == 0 {
				break
			}
			key := rows[0].Product + " " + rows[0].BranchOrTag + " " + rows[0].Variant
			if seen[key] {
				t.Fatalf("the page at %d repeats %s", offset, key)
			}
			seen[key] = true
		}
		if len(seen) != 3 {
			t.Errorf("pages of one held %d sightings, want all 3", len(seen))
		}
	})
}

func TestAnIssuesSightingsInPagesFollowTheOrderOfOneRead(t *testing.T) {
	// The affected-builds editor joins pages end to end and checks that each
	// opens on the last row of the one before, so a page read by offset holds
	// the rows one whole read holds there, in its order. Which order a
	// collation gives is held on every engine by the database package's own
	// test, since stored branch names are lower case.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		reported := []finding.Reported{found("CVE-2026-1", libnl)}
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.build, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"release-1", "apple", "zulu", "beta"} {
			build := f.anotherBranch(t, name)
			f.shippedTo(t, build, twoConsumers())
			if _, err := f.store.Apply(ctx, build, f.runOn(t, build), reported); err != nil {
				t.Fatal(err)
			}
		}
		who := f.holding(t, access.PublicRead)
		issue := f.issueID(t, "CVE-2026-1")
		whole, total, _, err := f.store.Everywhere(ctx, who, issue, f.productID, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 5 || len(whole) != 5 {
			t.Fatalf("one read held %d of %d, want 5 of 5, so this proves nothing", len(whole), total)
		}
		var names []string
		for _, row := range whole {
			names = append(names, row.BranchOrTag)
		}
		if !slices.IsSorted(names) {
			t.Errorf("one read ordered %v, want the names in order", names)
		}
		var paged []string
		for offset := 0; offset < total; offset += 2 {
			rows, _, _, err := f.store.Everywhere(ctx, who, issue, f.productID, 2, offset)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				paged = append(paged, row.BranchOrTag)
			}
		}
		if !slices.Equal(paged, names) {
			t.Errorf("pages of two joined to %v, one read ordered %v", paged, names)
		}
	})
}
