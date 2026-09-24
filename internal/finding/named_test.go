// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// builtFrom is a Debian binary built from curl at a source version.
func builtFrom(name, version string) graph.Described {
	return graph.Described{
		Purl: "pkg:deb/debian/" + name + "@" + version + "?upstream=curl",
		Name: name, Version: version,
		UpstreamName: "curl", UpstreamVersion: version,
	}
}

// rowOf is the component row a description was stored as.
func rowOf(t *testing.T, f *fixture, component graph.Described) int64 {
	t.Helper()
	var id int64
	if err := f.db.DB.NewSelect().TableExpr(`"component" AS "c"`).ColumnExpr("c.id").
		Where("c.identity = ?", component.Identity()).Scan(t.Context(), &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// hide makes every finding on one component undisclosed. Read first and then
// updated, because one engine refuses to name the table being updated inside
// a subquery of its own statement.
func hide(t *testing.T, f *fixture, component graph.Described) {
	t.Helper()
	id := rowOf(t, f, component)
	if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set("visibility = ?", access.Private).
		Where("component_id = ?", id).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestTwoSourceVersionsInOneBuildAreTwoEntriesAndOnePromiseEach(t *testing.T) {
	// A build vendoring one source at two versions holds two pieces of code.
	// Read, they are two entries; promised, the version on screen is the one
	// promised, and a promise naming neither is refused with both offered.
	each(t, func(t *testing.T, f *fixture) {
		older, newer := builtFrom("libcurl4t64", "8.5.0-2"), builtFrom("libcurl4t64", "8.11.0-1")
		f.shipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{root, swss, older, newer},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: older}, {Parent: root, Child: newer}},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-31", older), found("CVE-2026-32", newer),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		builds, err := f.store.AcrossBuilds(t.Context(), who, f.wholeProduct(), "libcurl4t64")
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 2 || builds[0].SourceVersion == builds[1].SourceVersion {
			t.Fatalf("%d entries for two source versions: %+v", len(builds), builds)
		}

		_, err = f.store.PlacesOnComponentWithin(t.Context(), f.db.DB, who, f.productID,
			[]int64{f.target}, "libcurl4t64", "")
		var several *graph.Ambiguous
		if !errors.As(err, &several) || len(several.Versions()) != 2 {
			t.Fatalf("a promise naming no version reached %v, want a refusal offering both", err)
		}

		reached, err := f.store.PlacesOnComponentWithin(t.Context(), f.db.DB, who, f.productID,
			[]int64{f.target}, "curl", "8.5.0-2")
		if err != nil {
			t.Fatal(err)
		}
		if len(reached) != 1 || reached[0].ComponentID != rowOf(t, f, older) {
			t.Errorf("a promise about 8.5.0-2 reached %+v, want the older binary alone", reached)
		}
	})
}

func TestAnUndisclosedFindingOnASiblingBinaryCountsForTheSourcePackage(t *testing.T) {
	// One source package is one handover: an embargoed finding on either
	// binary makes handing over the other the disclosure. And a reader of
	// disclosed work alone does not count it in the source's totals.
	each(t, func(t *testing.T, f *fixture) {
		lib, gnutls := builtFrom("libcurl4t64", "8.5.0-2"), builtFrom("libcurl3t64-gnutls", "8.5.0-2")
		f.shipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{root, swss, lib, gnutls},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: swss, Child: lib}, {Parent: swss, Child: gnutls}},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-41", lib), found("CVE-2026-42", gnutls),
		}); err != nil {
			t.Fatal(err)
		}
		hide(t, f, gnutls)

		both := f.holding(t, access.PublicTriage, access.PrivateTriage)
		strictest, err := f.store.StrictestOnComponent(t.Context(), both, f.productID,
			[]int64{f.target}, "libcurl4t64", "")
		if err != nil {
			t.Fatal(err)
		}
		if strictest != access.Private {
			t.Errorf("asked by the disclosed binary, the source reads as %q", strictest)
		}

		builds, err := f.store.AcrossBuilds(t.Context(), f.holding(t, access.PublicTriage),
			f.wholeProduct(), "curl")
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 || builds[0].Issues != 1 || builds[0].Places != 1 {
			t.Errorf("a reader of disclosed work reads %+v, want the disclosed issue alone", builds)
		}
	})
}

func TestANameResolvesToWhatTheBuildsAskedAboutShip(t *testing.T) {
	// One build ships a name at one version and another at a second. Asked
	// about the second build, the name reaches the second build's code,
	// whichever component row was written first.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, through(libnl))
		other := f.anotherBranch(t, "next")
		f.shippedTo(t, other, through(libnlNew))
		if _, err := f.store.Apply(t.Context(), other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-51", libnlNew),
		}); err != nil {
			t.Fatal(err)
		}
		hide(t, f, libnlNew)
		both := f.holding(t, access.PublicTriage, access.PrivateTriage)

		reached, err := f.store.PlacesOnComponentWithin(t.Context(), f.db.DB, both, f.productID,
			[]int64{other}, libnl.Name, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(reached) != 1 {
			t.Errorf("a promise for the second build reached %d places, want its one", len(reached))
		}
		strictest, err := f.store.StrictestOnComponent(t.Context(), both, f.productID,
			[]int64{other}, libnl.Name, "")
		if err != nil {
			t.Fatal(err)
		}
		if strictest != access.Private {
			t.Errorf("the second build's embargoed finding reads as %q", strictest)
		}
	})
}

func TestABlankNameReachesNothing(t *testing.T) {
	// Every component naming no source holds an empty source name, so a blank
	// name compared against it would reach all of them — and an upgrade has no
	// cap on what it writes.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-61", libnl), found("CVE-2026-62", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		for _, blank := range []string{"", " "} {
			reached, err := f.store.PlacesOnComponentWithin(t.Context(), f.db.DB, who, f.productID,
				[]int64{f.target}, blank, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(reached) != 0 {
				t.Errorf("%q reached %d places", blank, len(reached))
			}
		}
	})
}
