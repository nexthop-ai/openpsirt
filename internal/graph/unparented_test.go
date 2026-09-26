// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestWhatNothingPullsInHangsFromTheRoot(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		loose := at("libfoo", "1.0")
		// The root pulls in curl. zlib is pulled in by nothing and pulls in
		// openssl, and libfoo is pulled in by nothing and pulls in nothing.
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{curl, zlib, openssl, loose},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: curl},
				{Parent: zlib, Child: openssl},
			},
		}); err != nil {
			t.Fatal(err)
		}
		shared := f.anIssue(t, "CVE-2026-SHARED")
		deep := f.anIssue(t, "CVE-2026-DEEP")
		f.opens(t, shared, f.componentNamed(t, curl.Name), "under-root")
		f.opens(t, shared, f.componentNamed(t, loose.Name), "loose")
		f.opens(t, deep, f.componentNamed(t, openssl.Name), "under-zlib")

		top, kids, err := f.store.Roots(ctx, everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		beneath := map[string]int{}
		for _, kid := range kids {
			names = append(names, kid.Name)
			beneath[kid.Name] = kid.Beneath
		}
		slices.Sort(names)
		if want := []string{curl.Name, loose.Name, zlib.Name}; !slices.Equal(names, want) {
			t.Errorf("the root lists %v, want %v: what nothing pulls in is missing, or "+
				"what something pulls in is listed twice", names, want)
		}
		if beneath[zlib.Name] != 1 {
			t.Errorf("zlib has %d open beneath it, want the one at openssl", beneath[zlib.Name])
		}
		if top == nil {
			t.Fatal("the build's own root is missing")
		}
		if top.Children != len(kids) {
			t.Errorf("the root says it pulls in %d and lists %d", top.Children, len(kids))
		}
		// Two issues: the shared one is one issue at two components.
		if top.Beneath != 2 {
			t.Errorf("the root has %d open beneath it, want 2 counted as one set", top.Beneath)
		}
	})
}

func TestTheChoiceForAComponentWithNoNamespaceResolvesIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		bare := graph.Described{Purl: "pkg:docker/nginx@1.25", Name: "nginx", Version: "1.25"}
		named := graph.Described{Purl: "pkg:docker/library/nginx@1.25", Name: "nginx", Version: "1.25"}
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{bare, named},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: bare}, {Parent: root, Child: named},
			},
		}); err != nil {
			t.Fatal(err)
		}
		_, err := f.store.ComponentAs(ctx, f.targetID, "nginx", graph.Choice{Version: "1.25"})
		var several *graph.Ambiguous
		if !errors.As(err, &several) || len(several.Choices) != 2 {
			t.Fatalf("a name held twice answered %v, want the two choices", err)
		}
		// Each choice offered resolves exactly one component.
		for _, choice := range several.Choices {
			if _, err := f.store.ComponentAs(ctx, f.targetID, "nginx", choice); err != nil {
				t.Errorf("the choice %+v did not resolve: %v", choice, err)
			}
		}
	})
}

func TestACycleInTheEdgesEndsTheWalkAndCountsOnce(t *testing.T) {
	// Nothing bounds this walk's depth, so the union's refusal to add a pair
	// it already holds is the only thing that ends a cycle. On an engine where
	// it did not, this would not return.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{curl, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: curl},
				{Parent: curl, Child: zlib},
				{Parent: zlib, Child: curl},
			},
		}); err != nil {
			t.Fatal(err)
		}
		f.opens(t, f.anIssue(t, "CVE-2026-LOOP"), f.componentNamed(t, zlib.Name), "under-curl")

		top, kids, err := f.store.Roots(ctx, everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if top == nil || top.Beneath != 1 {
			t.Errorf("the root counts %+v beneath it, want the one issue", top)
		}
		if len(kids) != 1 || kids[0].Beneath != 1 {
			t.Errorf("curl counts %+v, want the one issue under it counted once", kids)
		}
	})
}

func TestASubtreeHoldingACycleIsEachComponentOnce(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{curl, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: curl},
				{Parent: curl, Child: zlib},
				{Parent: zlib, Child: curl},
			},
		}); err != nil {
			t.Fatal(err)
		}
		var ids []int64
		if err := graph.Within(f.db.DB, f.targetID, f.componentNamed(t, curl.Name)).
			Scan(ctx, &ids); err != nil {
			t.Fatal(err)
		}
		slices.Sort(ids)
		want := []int64{f.componentNamed(t, curl.Name), f.componentNamed(t, zlib.Name)}
		slices.Sort(want)
		if !slices.Equal(ids, want) {
			t.Errorf("the subtree under curl is %v, want curl and zlib once each (%v)", ids, want)
		}
	})
}

func TestWhatNothingCanMatchIsCounted(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		byName := graph.Described{Name: "bash", Version: "4.4.18-4.ph3"}
		byPlatform := graph.Described{Name: "busybox", Version: "1.36",
			CPE: "cpe:2.3:a:busybox:busybox:1.36:*:*:*:*:*:*:*"}
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{curl, byName, byPlatform},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: curl}, {Parent: root, Child: byName},
				{Parent: root, Child: byPlatform},
			},
		}); err != nil {
			t.Fatal(err)
		}
		tally, err := f.store.Counts(ctx, everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if tally.Components != 3 || tally.Unidentified != 1 {
			t.Errorf("counted %+v, want 3 components of which bash alone is unidentified", tally)
		}
	})
}

func TestTheChoiceForAComponentWithNoIdentifierResolvesIt(t *testing.T) {
	// apko describes a package once as an APK and once as a directory with no
	// identifier, at one name and one version.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		bare := graph.Described{Name: "gdbm", Version: "1.26-r6"}
		named := graph.Described{Purl: "pkg:apk/wolfi/gdbm@1.26-r6", Name: "gdbm", Version: "1.26-r6"}
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{bare, named},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: named}, {Parent: named, Child: bare},
			},
		}); err != nil {
			t.Fatal(err)
		}
		_, err := f.store.ComponentAs(ctx, f.targetID, "gdbm", graph.Choice{})
		var several *graph.Ambiguous
		if !errors.As(err, &several) || len(several.Choices) != 2 {
			t.Fatalf("a name held twice answered %v, want the two choices", err)
		}
		seen := map[int64]bool{}
		for _, choice := range several.Choices {
			id, err := f.store.ComponentAs(ctx, f.targetID, "gdbm", choice)
			if err != nil {
				t.Errorf("the choice %+v did not resolve: %v", choice, err)
			}
			seen[id] = true
		}
		if len(seen) != 2 {
			t.Errorf("the two choices resolved to %d components, want one each", len(seen))
		}
	})
}
