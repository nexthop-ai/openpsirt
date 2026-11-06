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
