// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"slices"
	"strings"
	"testing"

	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestAPackageIdentifierStartsAtEveryLiveComponentOfThatPackageAlone(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := graph.Described{Purl: "pkg:github/sonic-net/sonic-repo@1a2b", Name: "repo", Version: "1.0"}
		second := graph.Described{Purl: "pkg:github/sonic-net/sonic-repo@3c4d", Name: "repo", Version: "2.0"}
		// A longer name sharing the start, the same name in another kind, and
		// an underscore a pattern would read as any character.
		longer := graph.Described{Purl: "pkg:github/sonic-net/sonic-repo-common@5e6f", Name: "repo-common", Version: "1.0"}
		elsewhere := graph.Described{Purl: "pkg:deb/sonic-net/sonic-repo@1.0", Name: "repo", Version: "1.0"}
		odd := graph.Described{Purl: "pkg:githubx/sonic-net/sonic-repo@1", Name: "repo", Version: "3.0"}
		if _, err := fixtures.ApplyGraph(ctx, f.db, f.buildID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{first, second, longer, elsewhere, odd},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: first}, {Parent: root, Child: second}, {Parent: root, Child: longer},
				{Parent: root, Child: elsewhere}, {Parent: root, Child: odd},
			},
		}); err != nil {
			t.Fatal(err)
		}
		got, err := f.store.ComponentsOf(ctx, f.buildID, graph.ParsePurlPrefix("PKG:GitHub/sonic-net/sonic-repo"))
		if err != nil {
			t.Fatal(err)
		}
		want := []int64{f.componentWithPurl(t, first.Purl), f.componentWithPurl(t, second.Purl)}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("started at %v, want the two commits %v", got, want)
		}

		// A rescan moves the first commit and drops the longer name: the
		// closed commit is no start, and a package only closed nodes hold has
		// none, which the API answers as a package the build does not hold.
		third := graph.Described{Purl: "pkg:github/sonic-net/sonic-repo@7a8b", Name: "repo", Version: "3.0"}
		if _, err := fixtures.ApplyGraph(ctx, f.db, f.buildID, f.scan(t), graph.Snapshot{
			Root:       root,
			Components: []graph.Described{third, second, elsewhere, odd},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: third}, {Parent: root, Child: second},
				{Parent: root, Child: elsewhere}, {Parent: root, Child: odd},
			},
		}); err != nil {
			t.Fatal(err)
		}
		got, err = f.store.ComponentsOf(ctx, f.buildID, graph.ParsePurlPrefix("pkg:github/sonic-net/sonic-repo"))
		if err != nil {
			t.Fatal(err)
		}
		want = []int64{f.componentWithPurl(t, second.Purl), f.componentWithPurl(t, third.Purl)}
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("after the rescan started at %v, want the live commits %v", got, want)
		}
		gone, err := f.store.ComponentsOf(ctx, f.buildID, graph.ParsePurlPrefix("pkg:github/sonic-net/sonic-repo-common"))
		if err != nil {
			t.Fatal(err)
		}
		if len(gone) != 0 {
			t.Errorf("a package only closed nodes hold started at %v, want none", gone)
		}
	})
}

// A walk starts from what nothing pulls in only where the build's root is
// among its starts: the branch is priced at every node on MySQL and MariaDB,
// so a walk from below the root is written without it.
func TestAWalkFromBelowTheRootStartsAtItsStartsAlone(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := fixtures.ApplyGraph(ctx, f.db, f.buildID, f.scan(t), graph.Snapshot{
			Root: root, Components: []graph.Described{curl},
			Dependencies: []graph.Dependency{{Parent: root, Child: curl}},
		}); err != nil {
			t.Fatal(err)
		}
		top, below := f.componentNamed(t, root.Name), f.componentNamed(t, curl.Name)
		for _, c := range []struct {
			starts []int64
			root   bool
		}{{[]int64{below}, false}, {[]int64{below, top}, true}, {nil, false}} {
			got, err := graph.RootAmong(ctx, f.db.DB, f.buildID, c.starts)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.root {
				t.Errorf("starts %v hold the root: %v, want %v", c.starts, got, c.root)
			}
		}
		for fromRoot, seeds := range map[bool]bool{false: false, true: true} {
			written := graph.WithinAny(f.db.DB, f.buildID, []int64{below}, fromRoot).String()
			if strings.Contains(written, `"rn"`) != seeds {
				t.Errorf("from the root %v wrote the seeds of what nothing pulls in: %v, want %v",
					fromRoot, !seeds, seeds)
			}
		}
	})
}

// componentWithPurl is the identifier of the component a package identifier
// names.
func (f *fixture) componentWithPurl(t *testing.T, purl string) int64 {
	t.Helper()
	var id int64
	if err := f.db.DB.NewSelect().TableExpr(`"component" AS "c"`).
		ColumnExpr(`"c"."id"`).Where(`"c"."purl" = ?`, purl).
		Limit(1).Scan(t.Context(), &id); err != nil {
		t.Fatal(err)
	}
	return id
}
