// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"slices"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A package identifier chooses a package at every version a build holds it
// at, as the burndown chooses it: a longer name, the same name in another
// ecosystem and a type spelled as a prefix of another are left out, the page
// and the total agree, and the list across products takes it too.
func TestAPackageIdentifierKeepsThePackageAtEveryVersion(t *testing.T) {
	commitA := graph.Described{Purl: "pkg:github/sonic-net/sonic-swss@aaa111", Name: "sonic-swss", Version: "aaa111"}
	commitB := graph.Described{Purl: "pkg:github/sonic-net/sonic-swss@bbb222?arch=amd64", Name: "sonic-swss", Version: "bbb222"}
	longer := graph.Described{Purl: "pkg:github/sonic-net/sonic-swss-common@ccc333", Name: "sonic-swss-common", Version: "ccc333"}
	otherKind := graph.Described{Purl: "pkg:deb/debian/sonic-swss@1.0", Name: "sonic-swss", Version: "1.0"}
	nearType := graph.Described{Purl: "pkg:githubx/sonic-net/sonic-swss@aaa111", Name: "sonic-swss", Version: "aaa111"}
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{commitA, commitB, longer, otherKind, nearType},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: commitA}, {Parent: root, Child: commitB},
				{Parent: root, Child: longer}, {Parent: root, Child: otherKind},
				{Parent: root, Child: nearType},
			},
		})
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{
			found("CVE-2026-1", commitA), found("CVE-2026-1", commitB), found("CVE-2026-2", longer),
			found("CVE-2026-1", otherKind), found("CVE-2026-1", nearType),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		for _, c := range []struct {
			typed  string
			wanted []string
		}{
			{"pkg:github/sonic-net/sonic-swss", []string{"aaa111", "bbb222"}},
			{"PKG:GitHub/Sonic-Net/Sonic-SWSS@zzz?arch=arm64", []string{"aaa111", "bbb222"}},
			{"pkg:github/sonic-net/", []string{"aaa111", "bbb222", "ccc333"}},
			{"pkg:github/", []string{"aaa111", "bbb222", "ccc333"}},
			{"pkg:github/sonic-net/sonic-sw", nil},
		} {
			filter := finding.Filter{Purl: graph.ParsePurlPrefix(c.typed)}
			rows, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if got := githubVersions(rows); !slices.Equal(got, c.wanted) || total != len(c.wanted) {
				t.Errorf("%s kept %v (total %d), wanted %v", c.typed, got, total, c.wanted)
			}
			across, acrossTotal, err := f.store.Anywhere(t.Context(), who, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if got := githubVersions(across); !slices.Equal(got, c.wanted) || acrossTotal != len(c.wanted) {
				t.Errorf("%s kept %v across products (total %d), wanted %v", c.typed, got, acrossTotal, c.wanted)
			}
		}
	})
}

// githubVersions is the versions of the rows that are github packages,
// sorted, failing the comparison by holding any row of another kind.
func githubVersions(rows []finding.Group) []string {
	var out []string
	for _, r := range rows {
		if r.Ecosystem != "github" {
			out = append(out, r.Ecosystem+":"+r.Version)
			continue
		}
		out = append(out, r.Version)
	}
	slices.Sort(out)
	return out
}

// Every read over a Filter resolves its package identifier before narrowing
// by it: the identifier chooses rows where it names a package the build holds
// and none where it names nothing. A read that narrowed an unprepared filter
// would fail here rather than answer an empty list.
func TestEveryReadOverAFilterResolvesItsPackageIdentifier(t *testing.T) {
	swss := graph.Described{Purl: "pkg:github/sonic-net/sonic-swss@aaa111", Name: "sonic-swss", Version: "aaa111"}
	other := graph.Described{Purl: "pkg:deb/debian/curl@7.0", Name: "curl", Version: "7.0"}
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, graph.Snapshot{
			Root:         root,
			Components:   []graph.Described{swss, other},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: root, Child: other}},
		})
		f.applied(t, found("CVE-2026-1", swss), found("CVE-2026-2", other))
		who := f.planner(t, access.PublicTriage, access.Assigner)
		colleague, err := access.NewStore(f.db.DB).Ensure(ctx, "colleague@example.com", "Colleague", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		admits := func(context.Context, bun.IDB, []access.Visibility) error { return nil }

		reads := map[string]func(finding.Filter) (int, error){
			"component groups": func(filter finding.Filter) (int, error) {
				_, total, err := f.store.ComponentGroups(ctx, who, f.scope, 50, 0, filter)
				return total, err
			},
			"component group count": func(filter finding.Filter) (int, error) {
				return f.store.CountComponentGroups(ctx, who, f.scope, filter)
			},
			"planned upgrades": func(filter finding.Filter) (int, error) {
				_, total, err := f.store.PlannedUpgrades(ctx, who, f.scope, 50, 0, filter)
				return total, err
			},
			"planned upgrade count": func(filter finding.Filter) (int, error) {
				return f.store.CountPlannedUpgrades(ctx, who, f.scope, filter)
			},
			"hidden below a line": func(filter finding.Filter) (int, error) {
				filter.MinimumSeverity = finding.MinimumSeverity{Word: "critical"}
				return f.store.Hidden(ctx, who, f.scope, filter)
			},
			"assigning what matches": func(filter finding.Filter) (int, error) {
				handed, err := f.store.AssignMatching(ctx, who, f.scope, filter, nil, &colleague.ID, admits)
				return handed.Pieces, err
			},
		}
		for name, read := range reads {
			chosen, err := read(finding.Filter{Purl: graph.ParsePurlPrefix("pkg:github/sonic-net/sonic-swss")})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if chosen != 1 {
				t.Errorf("%s: the package the build holds counts %d, want 1", name, chosen)
			}
			none, err := read(finding.Filter{Purl: graph.ParsePurlPrefix("pkg:github/sonic-net/sonic-sw")})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if none != 0 {
				t.Errorf("%s: a package the build does not hold counts %d, want 0", name, none)
			}
		}
	})
}
