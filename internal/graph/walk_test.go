// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The three walks over a build's edges are recursive statements, and these pin
// what they answer on a constructed graph: the shortest way down to a
// component reached several ways, a component the inventory placed nowhere, a
// subtree with a shared library in it counted once, and a document in a loop.

// everyone is somebody granted reading on the product a fixture builds, for
// the walks whose subject is incidental. Not an administrator: administering
// is not reading, and reading is what these tests mean.
func everyone(f *fixture) access.Subject {
	return access.NewPerson(1, "tester", false,
		map[int64][]access.Role{*f.scope.ProductID: {access.PublicRead, access.PrivateRead}}, 0)
}

// chain spells a way down as words, root first.
func chain(steps []graph.Step) string {
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.Name)
	}
	return strings.Join(names, " > ")
}

func TestTheShortestWayDownIsTheOneShown(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// openssl is reached directly and through curl; libz only through
		// curl and then openssl, which is the longer of its two routes to
		// nothing — it has one. A component listed and placed nowhere has
		// no way down at all.
		unplaced := at("orphan", "0.1")
		snap := tree()
		snap.Components = append(snap.Components, zlib, unplaced)
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: openssl, Child: zlib})
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		ids := map[string]int64{}
		for _, name := range []string{"sonic", "curl", "openssl", "zlib", "orphan"} {
			id, err := f.store.ComponentAt(t.Context(), f.targetID, name)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			ids[name] = id
		}

		chains, err := f.store.Chains(t.Context(), everyone(f), f.targetID,
			[]int64{ids["sonic"], ids["curl"], ids["openssl"], ids["zlib"], ids["orphan"]})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"sonic":   "sonic",
			"curl":    "sonic > curl",
			"openssl": "sonic > openssl",
			"zlib":    "sonic > openssl > zlib",
		}
		for name, way := range want {
			if got := chain(chains[ids[name]]); got != way {
				t.Errorf("%s is reached by %q, wanted %q", name, got, way)
			}
		}
		if _, placed := chains[ids["orphan"]]; placed {
			t.Errorf("a component placed nowhere came back with a way down: %q", chain(chains[ids["orphan"]]))
		}
		// The version at each step, since that is what the complete
		// chain on a finding asks for.
		if steps := chains[ids["zlib"]]; len(steps) == 3 && steps[1].Version != openssl.Version {
			t.Errorf("the step through openssl carries version %q, wanted %q", steps[1].Version, openssl.Version)
		}
	})
}

func TestWhatIsBeneathACountsEachComponentOnce(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// Two containers each pull in the same library, which has two issues.
		// Each container is asked separately and answers with two; the root
		// answers with two as well, not four, and not eight for the places.
		a, b, lib := at("container-a", "1"), at("container-b", "1"), at("libshared", "1.0")
		snap := graph.Snapshot{
			Root:       root,
			Components: []graph.Described{a, b, lib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: a}, {Parent: root, Child: b},
				{Parent: a, Child: lib}, {Parent: b, Child: lib},
			},
		}
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		findings := finding.NewStore(f.store.DB())
		run, err := findings.Begin(t.Context(), finding.Run{
			TargetID: f.targetID, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-08-28", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		reported := func(id string, component graph.Described) finding.Reported {
			return finding.Reported{
				Issue:     finding.Named{Identifier: id, Severity: "high"},
				Component: component, FixState: finding.FixedUpstream, FixedIn: "2.0",
			}
		}
		if _, err := findings.Apply(t.Context(), f.targetID, run.ID, []finding.Reported{
			reported("CVE-2026-1", lib), reported("CVE-2026-2", lib), reported("CVE-2026-3", a),
		}); err != nil {
			t.Fatal(err)
		}

		top, kids, err := f.store.Roots(t.Context(), everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if top == nil || top.Beneath != 3 {
			t.Fatalf("the root reads %+v beneath, wanted 3 distinct issues", top)
		}
		for _, kid := range kids {
			want := 2
			if kid.Name == a.Name {
				want = 3
			}
			if kid.Beneath != want {
				t.Errorf("%s reads %d beneath, wanted %d", kid.Name, kid.Beneath, want)
			}
		}

		// The list a tree number opens agrees with it: narrowed beneath a
		// container, the findings list holds the library's two issues, and
		// beneath the root everything.
		aID, err := f.store.ComponentAt(t.Context(), f.targetID, a.Name)
		if err != nil {
			t.Fatal(err)
		}
		_, total, err := findings.Groups(t.Context(), everyone(f), f.scope, 50, 0,
			finding.Filter{Beneath: &aID})
		if err != nil {
			t.Fatal(err)
		}
		if total != 3 {
			t.Errorf("beneath %s the list counts %d groups, wanted 3", a.Name, total)
		}
		bID, err := f.store.ComponentAt(t.Context(), f.targetID, b.Name)
		if err != nil {
			t.Fatal(err)
		}
		_, total, err = findings.Groups(t.Context(), everyone(f), f.scope, 50, 0,
			finding.Filter{Beneath: &bID})
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 {
			t.Errorf("beneath %s the list counts %d groups, wanted 2", b.Name, total)
		}
	})
}

func TestADocumentInALoopIsWalkedOnceAndStops(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// a depends on b, b on a, and the product on a. Every walk has to
		// come back, and the components in the loop are still placed.
		a, b := at("a", "1"), at("b", "1")
		snap := graph.Snapshot{
			Root:       root,
			Components: []graph.Described{a, b},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: a}, {Parent: a, Child: b}, {Parent: b, Child: a},
			},
		}
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		aID, _ := f.store.ComponentAt(t.Context(), f.targetID, "a")
		bID, _ := f.store.ComponentAt(t.Context(), f.targetID, "b")

		chains, err := f.store.Chains(t.Context(), everyone(f), f.targetID, []int64{aID, bID})
		if err != nil {
			t.Fatal(err)
		}
		if got := chain(chains[bID]); got != "sonic > a > b" {
			t.Errorf("b is reached by %q, wanted the way that does not loop", got)
		}
		root, kids, err := f.store.Roots(t.Context(), everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if root == nil || len(kids) != 1 || kids[0].Beneath != 0 {
			t.Errorf("the tree under a loop reads root %+v, children %+v", root, kids)
		}
	})
}

func TestContainersAreOrderedByWhatIsInsideThem(t *testing.T) {
	// A container holds no findings of its own. Ranked on its own count every
	// one of them is zero, the order falls back to the name, and the tree
	// opens as an alphabetical list of containers that says nothing about
	// which is worth opening — which is what it looked like on a real image.
	//
	// The number a row is ranked on is the number that describes it: for a
	// branch, everything open beneath it.
	each(t, func(t *testing.T, f *fixture) {
		// Named so that alphabetical and by-findings are opposite orders, or
		// the test passes on either.
		quiet, busy := at("aaa-container", "1"), at("zzz-container", "1")
		small, large := at("libsmall", "1.0"), at("liblarge", "1.0")
		snap := graph.Snapshot{
			Root:       root,
			Components: []graph.Described{quiet, busy, small, large},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: quiet}, {Parent: root, Child: busy},
				{Parent: quiet, Child: small}, {Parent: busy, Child: large},
			},
		}
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		findings := finding.NewStore(f.store.DB())
		run, err := findings.Begin(t.Context(), finding.Run{
			TargetID: f.targetID, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-08-28", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		reported := func(id string, component graph.Described) finding.Reported {
			return finding.Reported{
				Issue:     finding.Named{Identifier: id, Severity: "high"},
				Component: component, FixState: finding.FixedUpstream, FixedIn: "2.0",
			}
		}
		if _, err := findings.Apply(t.Context(), f.targetID, run.ID, []finding.Reported{
			reported("CVE-2026-1", large), reported("CVE-2026-2", large),
			reported("CVE-2026-3", small),
		}); err != nil {
			t.Fatal(err)
		}

		_, kids, err := f.store.Roots(t.Context(), everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if len(kids) != 2 {
			t.Fatalf("%d children of the root, want the two containers", len(kids))
		}
		if kids[0].Name != busy.Name {
			t.Errorf("the tree opens with %q holding %d, ahead of %q holding %d — "+
				"ordered by the name rather than by what is inside",
				kids[0].Name, kids[0].Beneath, kids[1].Name, kids[1].Beneath)
		}
		// And neither container holds anything of its own, which is the whole
		// reason its own count cannot be what it is ranked on.
		for _, kid := range kids {
			if kid.Findings != 0 {
				t.Errorf("%s holds %d findings of its own, so this proves nothing",
					kid.Name, kid.Findings)
			}
		}
	})
}

func TestWhatIsBeneathANodeSaysWhatItIsMadeOf(t *testing.T) {
	// A node saying five thousand beneath it says nothing about whether any of
	// it matters, which is exactly what somebody deciding where to descend is
	// asking. The bands sum back to the total, because an issue has one
	// rating — so the number and its parts cannot disagree.
	each(t, func(t *testing.T, f *fixture) {
		box, lib := at("container-a", "1"), at("libshared", "1.0")
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{box, lib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: box}, {Parent: box, Child: lib},
			},
		}); err != nil {
			t.Fatal(err)
		}
		findings := finding.NewStore(f.store.DB())
		run, err := findings.Begin(t.Context(), finding.Run{
			TargetID: f.targetID, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-08-28", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		rated := func(id, band string) finding.Reported {
			return finding.Reported{
				Issue:     finding.Named{Identifier: id, Severity: band},
				Component: lib,
			}
		}
		if _, err := findings.Apply(t.Context(), f.targetID, run.ID, []finding.Reported{
			rated("CVE-2026-1", "critical"), rated("CVE-2026-2", "low"),
			// Nobody rated this one, which is its own band rather than a row
			// the split quietly drops.
			rated("CVE-2026-3", ""),
		}); err != nil {
			t.Fatal(err)
		}

		root, kids, err := f.store.Roots(t.Context(), everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		// The root carries the split too. Its own number is counted in the
		// same statement as its children's, and the root is the one node a
		// reader sees before deciding whether to descend at all.
		if root == nil {
			t.Fatal("the build named a root and none came back")
		}
		rootSum := 0
		for _, n := range root.BeneathBy {
			rootSum += n
		}
		if rootSum != root.Beneath || root.Beneath == 0 {
			t.Errorf("the root's split %+v does not sum to its %d beneath",
				root.BeneathBy, root.Beneath)
		}
		var one *graph.Neighbor
		for i := range kids {
			if kids[i].Name == box.Name {
				one = &kids[i]
			}
		}
		if one == nil {
			t.Fatalf("the container is not under the root: %+v", kids)
		}
		if one.Beneath != 3 {
			t.Fatalf("%d issues beneath, want the three", one.Beneath)
		}
		// The word as the data has it. Folding a rating nobody recognizes into
		// one word is the reader's question, and it is answered where the API
		// shapes the answer — this package cannot reach the list that says
		// which words are real without an import cycle.
		if one.BeneathBy["critical"] != 1 || one.BeneathBy["low"] != 1 ||
			one.BeneathBy[""] != 1 {
			t.Errorf("the split is %+v, want one of each", one.BeneathBy)
		}
		sum := 0
		for _, n := range one.BeneathBy {
			sum += n
		}
		if sum != one.Beneath {
			t.Errorf("the split sums to %d and the count says %d", sum, one.Beneath)
		}
	})
}

func TestAProductsOwnRatingDrawsTheTreeTheBundleStripAndTheReleaseNote(t *testing.T) {
	// One rule for what a finding's severity is: this product's word where it
	// has stated one, the published word otherwise. Nine queries read the
	// published word alone with no rating joined, so a product that re-rated
	// an issue saw its own decision in the findings list and the world's in
	// the tree, the component strip and the document it publishes — three
	// surfaces disagreeing with the list they summarize.
	//
	// The three are asserted together because what broke them is one thing:
	// the expression is now spelled in one place and none of them can read it
	// without joining the rating it comes from.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		lib := at("libshared", "1.0")
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root: root, Components: []graph.Described{lib},
			Dependencies: []graph.Dependency{{Parent: root, Child: lib}},
		}); err != nil {
			t.Fatal(err)
		}
		findings := finding.NewStore(f.store.DB())
		run, err := findings.Begin(ctx, finding.Run{
			TargetID: f.targetID, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-08-28", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := findings.Apply(ctx, f.targetID, run.ID, []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-9", Severity: "low"},
			Component: lib, FixState: finding.FixedUpstream, FixedIn: "2.0",
		}}); err != nil {
			t.Fatal(err)
		}

		who := everyone(f)
		// Each of the three ratings for the issue, read the same way
		// before and after.
		treeBand := func(t *testing.T) string {
			t.Helper()
			_, kids, err := f.store.Roots(ctx, who, f.targetID)
			if err != nil {
				t.Fatal(err)
			}
			for _, kid := range kids {
				if kid.Name == lib.Name {
					return oneBand(t, "the tree", kid.BeneathBy)
				}
			}
			t.Fatalf("the library is not under the root")
			return ""
		}
		stripBand := func(t *testing.T) string {
			t.Helper()
			groups, _, err := findings.ComponentGroups(ctx, who, f.scope, 50, 0, finding.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			if len(groups) != 1 {
				t.Fatalf("the strip covers %d components, wanted the one", len(groups))
			}
			return oneBand(t, "the strip", groups[0].BySeverity)
		}
		noteBand := func(t *testing.T) string {
			t.Helper()
			// A build compared against itself: every row is unchanged, which
			// is what carries the severity the document would publish.
			changed, err := findings.Compare(ctx, who, f.targetID, f.targetID, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(changed.Still) != 1 {
				t.Fatalf("the comparison holds %d rows, wanted the one", len(changed.Still))
			}
			return changed.Still[0].Severity
		}

		for what, band := range map[string]string{
			"tree": treeBand(t), "strip": stripBand(t), "note": noteBand(t),
		} {
			if band != "low" {
				t.Errorf("before anybody re-rated it, %s says %q, wanted the published \"low\"",
					what, band)
			}
		}

		// The product says it is worse than the world does, which is the
		// whole point of being able to rate an issue here.
		issue := f.anIssue(t, "CVE-2026-9")
		if _, err := f.db.DB.NewInsert().Model(&finding.IssueRating{
			VulnerabilityID: issue, ProductID: *f.scope.ProductID, Severity: "critical",
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		for what, band := range map[string]string{
			"tree": treeBand(t), "strip": stripBand(t), "note": noteBand(t),
		} {
			if band != "critical" {
				t.Errorf("after this product rated it critical, %s still says %q", what, band)
			}
		}
	})
}

// oneBand is the single band a count is all of, named so a failure says which
// of the three surfaces disagreed.
func oneBand(t *testing.T, what string, counts map[string]int) string {
	t.Helper()
	if len(counts) != 1 {
		t.Fatalf("%s is banded %v, wanted one band holding the one issue", what, counts)
	}
	for band := range counts {
		return band
	}
	return ""
}
