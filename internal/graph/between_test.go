// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Which names two builds differ on, as each stands now. Any two builds of a
// product: two releases, two platforms of one release, a tag and its branch.

// taggedBuild is the fixture's tag built as the customer variant, a second
// build of the same product with nothing read for it yet.
func taggedBuild(t *testing.T, f *fixture) int64 {
	t.Helper()
	return f.world.TargetFor(f.world.Tag, f.world.Customer).ID
}

// appliedTo reads one inventory for any build.
func appliedTo(t *testing.T, f *fixture, targetID int64, snap graph.Snapshot) {
	t.Helper()
	if _, err := f.store.Apply(t.Context(), targetID, f.scanOf(t, targetID), snap); err != nil {
		t.Fatal(err)
	}
}

// holding is an inventory of the product root and these components directly
// beneath it.
func holding(components ...graph.Described) graph.Snapshot {
	return under(root, components...)
}

// under is an inventory of these components directly beneath a root.
func under(top graph.Described, components ...graph.Described) graph.Snapshot {
	snap := graph.Snapshot{Root: top, Components: components}
	for _, component := range components {
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: top, Child: component})
	}
	return snap
}

// between asks for the whole difference between two builds.
func between(t *testing.T, f *fixture, fromID, toID int64) []graph.Change {
	t.Helper()
	listed, total, err := f.store.Between(t.Context(), everyone(f), fromID, toID, "", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != len(listed) {
		t.Errorf("the whole listing is %d rows and the total says %d", len(listed), total)
	}
	return listed
}

func TestTwoBuildsDifferByWhatArrivedWentAndMoved(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		tag := taggedBuild(t, f)
		// The tag holds openssl, curl and a vendored second openssl; the
		// branch has dropped curl, moved one openssl and taken zlib. The
		// shared name at a shared version is no change, and neither is the
		// root, which names each build differently and is not one of its
		// own components.
		vendored := at("openssl", "1.1.1w")
		appliedTo(t, f, tag, under(at("sonic-broadcom", "2.4.1"), openssl, vendored, curl))
		applied(t, f, holding(at("openssl", "3.0.12"), vendored, zlib))

		got := spelled(between(t, f, tag, f.targetID))
		want := []string{
			"removed curl [8.4.0] -> []",
			"added zlib [] -> [1.3]",
			"changed openssl [1.1.1w 3.0.11] -> [1.1.1w 3.0.12]",
		}
		if strings.Join(got, "; ") != strings.Join(want, "; ") {
			t.Errorf("the difference reads\n%v\nwant\n%v", got, want)
		}

		// The other way round is the same difference read from the other
		// side: what one build gained the other lost.
		got = spelled(between(t, f, f.targetID, tag))
		want = []string{
			"removed zlib [1.3] -> []",
			"added curl [] -> [8.4.0]",
			"changed openssl [1.1.1w 3.0.12] -> [1.1.1w 3.0.11]",
		}
		if strings.Join(got, "; ") != strings.Join(want, "; ") {
			t.Errorf("reversed, the difference reads\n%v\nwant\n%v", got, want)
		}
	})
}

func TestABuildIsComparedAsItStandsNow(t *testing.T) {
	// A build's earlier uploads are its history, not its contents. A name it
	// held once and no longer holds is not on its side of a comparison.
	each(t, func(t *testing.T, f *fixture) {
		tag := taggedBuild(t, f)
		appliedTo(t, f, tag, holding(openssl))
		applied(t, f, holding(openssl, curl))
		applied(t, f, holding(openssl))

		if got := between(t, f, tag, f.targetID); len(got) != 0 {
			t.Errorf("two builds holding the same thing now differ by %v", spelled(got))
		}
	})
}

func TestOneBuildComparedWithItselfDiffersInNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		if got := between(t, f, f.targetID, f.targetID); len(got) != 0 {
			t.Errorf("a build compared with itself differs by %v", spelled(got))
		}
	})
}

func TestANameSpelledTwoWaysIsOneName(t *testing.T) {
	// Identity is the folded name. Two producers capitalizing one dependency
	// differently are describing one dependency, and that is no arrival and
	// no departure.
	each(t, func(t *testing.T, f *fixture) {
		tag := taggedBuild(t, f)
		appliedTo(t, f, tag, holding(graph.Described{
			Purl: "pkg:generic/OpenSSL@3.0.11", Name: "OpenSSL", Version: "3.0.11",
		}))
		applied(t, f, holding(openssl))

		if got := between(t, f, tag, f.targetID); len(got) != 0 {
			t.Errorf("one name in two spellings differs by %v", spelled(got))
		}
	})
}

func TestABuildWithNoInventoryIsNotCompared(t *testing.T) {
	// Compared against nothing, every name the other build holds would read
	// as added, which says something about a build nobody has described.
	each(t, func(t *testing.T, f *fixture) {
		applied(t, f, tree())
		tag := taggedBuild(t, f)
		for _, pair := range [][2]int64{{tag, f.targetID}, {f.targetID, tag}} {
			_, _, err := f.store.Between(t.Context(), everyone(f), pair[0], pair[1], "", 0, 0)
			if !errors.Is(err, graph.ErrNoInventory) {
				t.Errorf("comparing %d with %d answered %v, want no inventory", pair[0], pair[1], err)
			}
		}
	})
}

func TestADifferenceIsNarrowedAndPagedAfterItIsWorkedOut(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		tag := taggedBuild(t, f)
		appliedTo(t, f, tag, holding(openssl))
		applied(t, f, holding(openssl, curl, zlib))

		listed, total, err := f.store.Between(t.Context(), everyone(f), tag, f.targetID,
			graph.Added, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 || len(listed) != 1 || listed[0].Name != "zlib" {
			t.Errorf("the second page of one arrivals reads %v of %d, want zlib of 2",
				spelled(listed), total)
		}
	})
}

func TestTwoBuildsAreComparedOnlyForSomebodyWhoSeesThem(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		tag := taggedBuild(t, f)
		appliedTo(t, f, tag, holding(openssl))
		applied(t, f, holding(curl))

		outsider := access.NewPerson(2, "outsider", false, nil, 0)
		if _, _, err := f.store.Between(t.Context(), outsider, tag, f.targetID, "", 0, 0); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody outside the product was answered with %v, want a refusal", err)
		}
	})
}
