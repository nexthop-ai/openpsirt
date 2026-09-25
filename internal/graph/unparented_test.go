// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
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
