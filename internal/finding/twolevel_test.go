// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// curlFold ships two binaries of one source at one version, which is one fold,
// each carrying the same issue with a fixed version.
func (f *fixture) curlFold(t *testing.T) (lib, tool graph.Described) {
	t.Helper()
	lib = graph.Described{
		Purl: "pkg:deb/debian/libcurl4t64@8.5.0", Name: "libcurl4t64", Version: "8.5.0",
		UpstreamName: "curl", UpstreamVersion: "8.5.0",
	}
	tool = graph.Described{
		Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0",
		UpstreamName: "curl", UpstreamVersion: "8.5.0",
	}
	f.shipped(t, graph.Snapshot{
		Root:       root,
		Components: []graph.Described{lib, tool},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: lib}, {Parent: root, Child: tool},
		},
	})
	fixed := func(component graph.Described) finding.Reported {
		return finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-CURL", Severity: "high"},
			Component: component, FixState: finding.FixedUpstream, FixedIn: "8.6.0",
		}
	}
	if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
		[]finding.Reported{fixed(lib), fixed(tool)}); err != nil {
		t.Fatal(err)
	}
	return lib, tool
}

// A condition over a group is asked of every package in its fold. The list
// groups the places by issue and component first and by fold second, and a
// state is a condition over the second: a fold with one package decided and
// one not is neither undecided nor agreed, rather than one row of each.
func TestAGroupsStateIsAskedOfEveryPackageInItsFold(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		lib, tool := f.curlFold(t)
		who := f.holding(t, access.PublicTriage)
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "somebody@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		issue := f.issue(t, "CVE-2026-CURL")
		f.decided(t, somebody.ID, issue, finding.PlaceIdentity(lib.Name, ""), "approved", lib.Version, "lib")

		count := func(states ...finding.ClaimStanding) int {
			t.Helper()
			groups, total, err := f.store.Groups(ctx, who, f.scope, 50, 0, finding.Filter{States: states})
			if err != nil {
				t.Fatal(err)
			}
			if len(groups) != total {
				t.Fatalf("%v: a page of %d rows says there are %d", states, len(groups), total)
			}
			for _, group := range groups {
				if group.Places != 2 {
					t.Errorf("%v: the fold's row counts %d places, want both packages'", states, group.Places)
				}
			}
			return total
		}
		if n := count(); n != 1 {
			t.Fatalf("the fold is %d rows, want one", n)
		}
		if n := count(finding.StandingUndecided); n != 0 {
			t.Errorf("a fold with one package decided reads as undecided in %d rows", n)
		}
		if n := count(finding.StandingAgreed); n != 0 {
			t.Errorf("a fold with one package decided reads as agreed in %d rows", n)
		}

		f.decided(t, somebody.ID, issue, finding.PlaceIdentity(tool.Name, ""), "approved", tool.Version, "tool")
		if n := count(finding.StandingAgreed); n != 1 {
			t.Errorf("a fold with every package decided reads as agreed in %d rows, want one", n)
		}
		if n := count(finding.StandingUndecided); n != 0 {
			t.Errorf("a fold with every package decided reads as undecided in %d rows", n)
		}
	})
}

// The fold is counted once by every count of the list, and its places are
// both packages' places, whichever statement does the counting: the page, the
// count behind an empty page, the list across products, the hidden count, and
// the two other views with and without a page.
func TestAFoldIsOneRowInEveryCountOfTheList(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.curlFold(t)
		who := f.holding(t, access.PublicTriage)

		for name, filter := range map[string]finding.Filter{
			"no filter": {},
			"has a fix": {HasFix: true},
			"by age":    {SortBy: finding.ByAge},
			"undecided": {States: []finding.ClaimStanding{finding.StandingUndecided}},
		} {
			groups, total, err := f.store.Groups(ctx, who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if total != 1 || len(groups) != 1 || groups[0].Places != 2 || groups[0].Packages != 2 {
				t.Fatalf("%s: the page is %+v (total %d), want one row of two packages' places",
					name, groups, total)
			}
			if _, past, err := f.store.Groups(ctx, who, f.scope, 50, 50, filter); err != nil || past != 1 {
				t.Errorf("%s: a page past the end counts %d (%v), want the one fold", name, past, err)
			}
			across, all, err := f.store.Anywhere(ctx, who, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if all != 1 || len(across) != 1 || across[0].Places != 2 {
				t.Errorf("%s: across products the fold is %+v (total %d)", name, across, all)
			}
			if _, past, err := f.store.Anywhere(ctx, who, 50, 50, filter); err != nil || past != 1 {
				t.Errorf("%s: across products a page past the end counts %d (%v)", name, past, err)
			}
		}

		hidden, err := f.store.Hidden(ctx, who, f.scope, finding.Filter{Floor: finding.Floor{Word: "critical"}})
		if err != nil {
			t.Fatal(err)
		}
		if hidden != 1 {
			t.Errorf("a line above the fold's rating hides %d rows, want the one fold", hidden)
		}

		components, byComponent, err := f.store.ComponentGroups(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if byComponent != 2 || len(components) != 2 {
			t.Errorf("by component the fold is %d rows (total %d), want one per package", len(components), byComponent)
		}
		for _, component := range components {
			if component.Issues != 1 || component.Places != 1 {
				t.Errorf("%s carries %d issues at %d places, want one at one",
					component.Component, component.Issues, component.Places)
			}
		}
		alone, err := f.store.CountComponentGroups(ctx, who, f.scope, finding.Filter{})
		if err != nil || alone != byComponent {
			t.Errorf("by component the total alone is %d (%v), and the page says %d", alone, err, byComponent)
		}

		bundles, byBump, err := f.store.Bundles(ctx, who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if byBump != 1 || len(bundles) != 1 || bundles[0].Places != 2 || bundles[0].Issues != 1 ||
			len(bundles[0].Components) != 2 {
			t.Errorf("by upgrade the fold is %+v (total %d), want one bump of both packages", bundles, byBump)
		}
		bumps, err := f.store.CountBundles(ctx, who, f.scope, finding.Filter{})
		if err != nil || bumps != byBump {
			t.Errorf("by upgrade the total alone is %d (%v), and the page says %d", bumps, err, byBump)
		}
	})
}

func TestABundleNamesEachPackageAndBuildOnceInNameOrder(t *testing.T) {
	// A fold of two packages, each with two issues the same version fixes,
	// shipped in two builds, beside a bundle of another fold. Each bundle
	// names its own packages and builds, once each, in the order a reader
	// scans them, however many places and issues sit under a name.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		lib := graph.Described{
			Purl: "pkg:deb/debian/libcurl4t64@8.5.0", Name: "libcurl4t64", Version: "8.5.0",
			UpstreamName: "curl", UpstreamVersion: "8.5.0",
		}
		tool := graph.Described{
			Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0",
			UpstreamName: "curl", UpstreamVersion: "8.5.0",
		}
		zlib := graph.Described{Purl: "pkg:deb/debian/zlib1g@1.3", Name: "zlib1g", Version: "1.3"}
		snapshot := graph.Snapshot{
			Root:       root,
			Components: []graph.Described{lib, tool, zlib},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: lib}, {Parent: root, Child: tool}, {Parent: root, Child: zlib},
			},
		}
		fixed := func(issue string, component graph.Described, in string) finding.Reported {
			return finding.Reported{
				Issue:     finding.Named{Identifier: issue, Severity: "high"},
				Component: component, FixState: finding.FixedUpstream, FixedIn: in,
			}
		}
		curl := []finding.Reported{
			fixed("CVE-2026-CURL-1", lib, "8.6.0"), fixed("CVE-2026-CURL-1", tool, "8.6.0"),
			fixed("CVE-2026-CURL-2", lib, "8.6.0"), fixed("CVE-2026-CURL-2", tool, "8.6.0"),
		}
		f.shipped(t, snapshot)
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			append(curl, fixed("CVE-2026-ZLIB", zlib, "1.3.1"))); err != nil {
			t.Fatal(err)
		}
		other := f.anotherBuild(t, "2026.09")
		f.shippedTo(t, other, snapshot)
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), curl); err != nil {
			t.Fatal(err)
		}

		bundles, _, err := f.store.Bundles(ctx, f.holding(t, access.PublicTriage), f.wholeProduct(),
			50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		named := map[string]finding.Bundle{}
		for _, bundle := range bundles {
			named[bundle.To] = bundle
		}
		if got := named["8.6.0"].Components; len(got) != 2 || got[0] != "curl" || got[1] != "libcurl4t64" {
			t.Errorf("the curl bundle names %v, want curl and libcurl4t64 once each, in name order", got)
		}
		builds := named["8.6.0"].In
		if len(builds) != 2 || builds[0] == builds[1] ||
			builds[0].Stream > builds[1].Stream {
			t.Errorf("the curl bundle is in %v, want its two builds once each, in name order", builds)
		}
		if got := named["1.3.1"]; len(got.Components) != 1 || got.Components[0] != "zlib1g" ||
			len(got.In) != 1 {
			t.Errorf("the zlib bundle names %v in %v, want zlib1g in the one build shipping it",
				got.Components, got.In)
		}
	})
}
