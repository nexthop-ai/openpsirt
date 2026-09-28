// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestANameShapedLikeAPackageIdentifierIsNotThatPackage(t *testing.T) {
	// A package identifier and a name with a version are two bases, and one
	// is never mistaken for the other: a component nobody gave an identifier
	// would otherwise take the real package's row, and whichever arrived
	// first would decide for every product whether a scanner can match it.
	for _, pair := range [][2]graph.Described{
		{{Name: "pkg:npm/lodash", Version: "4.17.22"}, {Purl: "pkg:npm/lodash@4.17.22"}},
		// And a separator inside a name or a version moves nothing across.
		{{Name: "a@b", Version: "c"}, {Name: "a", Version: "b@c"}},
		// Including a byte a producer's JSON can spell and three of the four
		// engines store.
		{{Name: "a\x00b", Version: "c"}, {Name: "a", Version: "b\x00c"}},
	} {
		if pair[0].Identity() == pair[1].Identity() {
			t.Errorf("%+v and %+v are one component", pair[0], pair[1])
		}
	}

	each(t, func(t *testing.T, f *fixture) {
		components := graph.NewComponents(f.db.DB)
		shaped := graph.Described{Name: "pkg:npm/lodash", Version: "4.17.22"}
		real := graph.Described{Purl: "pkg:npm/lodash@4.17.22", Name: "lodash", Version: "4.17.22"}
		ids, err := components.Intern(t.Context(), []graph.Described{shaped})
		if err != nil {
			t.Fatal(err)
		}
		later, err := components.Intern(t.Context(), []graph.Described{real})
		if err != nil {
			t.Fatal(err)
		}
		if ids[shaped.Identity()] == later[real.Identity()] {
			t.Error("the real package was stored on the row a name shaped like it made")
		}
	})
}

func TestEachBuildHandsTheScannerTheIdentifiersItStated(t *testing.T) {
	// One package at one version is one component across every product, and
	// what each build states about it is its own: the distribution release a
	// qualifier names decides which advisories a scanner matches. What a
	// build does not state is taken from the shared row.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other := f.world.TargetFor(f.world.Branch, f.world.Internal).ID
		stating := func(distro, cpe string) graph.Snapshot {
			busybox := graph.Described{
				Purl: "pkg:apk/alpine/busybox@1.37.0-r31?distro=" + distro,
				CPE:  cpe, Name: "busybox", Version: "1.37.0-r31",
			}
			return graph.Snapshot{
				Root:         root,
				Components:   []graph.Described{busybox},
				Dependencies: []graph.Dependency{{Parent: root, Child: busybox}},
			}
		}
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t),
			stating("alpine-3.24.1", "cpe:2.3:a:busybox:busybox:1.37.0")); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(ctx, other, f.scanOf(t, other), stating("alpine-3.23.4", "")); err != nil {
			t.Fatal(err)
		}
		said := func(target int64) graph.Described {
			t.Helper()
			held, err := f.store.CurrentComponents(ctx, target)
			if err != nil {
				t.Fatal(err)
			}
			if len(held) != 1 {
				t.Fatalf("the build holds %+v, want busybox alone", held)
			}
			return held[0]
		}
		// Its own distribution stands; the enumeration it did not state is
		// the one the shared row was filled in with.
		if got := said(other); got.Purl != "pkg:apk/alpine/busybox@1.37.0-r31?distro=alpine-3.23.4" ||
			got.CPE != "cpe:2.3:a:busybox:busybox:1.37.0" {
			t.Errorf("the second build hands the scanner %q and %q, want its own distribution"+
				" and the enumeration the first stated", got.Purl, got.CPE)
		}
		if got := said(f.targetID); got.CPE == "" {
			t.Errorf("the first build hands the scanner no enumeration, and it stated one")
		}

		// A distribution release moving under an unchanged version is written
		// on the node, and opens and closes nothing.
		applied, err := f.store.Apply(ctx, f.targetID, f.scan(t),
			stating("alpine-3.24.2", "cpe:2.3:a:busybox:busybox:1.37.0"))
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("restating an identifier opened or closed something: %+v", applied)
		}
		if got := said(f.targetID); got.Purl != "pkg:apk/alpine/busybox@1.37.0-r31?distro=alpine-3.24.2" {
			t.Errorf("after the build restated it, the scanner is handed %q", got.Purl)
		}
	})
}
