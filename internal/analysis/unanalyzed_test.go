// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// A build never analyzed is found by the name it stated for a component, in
// any capitals, where another product described the package first under
// another name, and never by a name only another build stated; and every
// build is found by the name the component row holds.
func TestABuildNeverAnalyzedIsFoundByTheNameItStated(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		scans := ingest.NewStore(w.DB.DB)
		built := time.Now().UTC().Add(-time.Hour)
		apply := func(build int64, d graph.Described) {
			t.Helper()
			built = built.Add(time.Minute)
			scan, _, err := scans.Record(ctx, ingest.Arriving{
				BuildID: build, ContentHash: fmt.Sprintf("hash-%d-%s", build, d.Name),
				BuiltAt: built, ParserVersion: "test",
			})
			if err != nil {
				t.Fatal(err)
			}
			root := graph.Described{Name: "box", Version: "1.0"}
			if _, err := fixture.ApplyGraph(ctx, w.DB.DB, build, scan.ID, graph.Snapshot{
				Root: root, Components: []graph.Described{d},
				Dependencies: []graph.Dependency{{Parent: root, Child: d}},
			}); err != nil {
				t.Fatal(err)
			}
		}
		other := w.DeclareProduct("edge", "Edge")
		theirs := w.BuildFor(w.DeclareBranchOrTag(other, "main", catalog.Branch, nil),
			w.DeclareVariant(other, "box", true)).ID
		const purl = "pkg:deb/debian/openssl@3.0.11-1"
		apply(theirs, graph.Described{Purl: purl, Name: "nothing", Version: "99.0"})
		apply(w.Build.ID, graph.Described{Purl: purl, Name: "openssl", Version: "3.0.11-1"})
		// A second build of the product calls the same package by another
		// name, so a lookup by the first build's word does not reach it.
		renamed := w.BuildFor(w.DeclareBranchOrTag(w.Product, "next", catalog.Branch, nil), w.Customer).ID
		apply(renamed, graph.Described{Purl: purl, Name: "libssl", Version: "3.0.11-1"})

		for typed, want := range map[string][]int64{
			"OpenSSL": {w.Build.ID}, "libssl": {renamed}, "nothing": {w.Build.ID, renamed},
		} {
			found, err := unanalyzed(ctx, w.DB.DB, w.Product.ID, 0, typed, graph.Choice{})
			if err != nil {
				t.Fatal(err)
			}
			got := make([]int64, 0, len(found))
			for _, b := range found {
				got = append(got, b.BuildID)
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("typed %q, the builds never analyzed are %v, want %v", typed, got, want)
			}
		}
		// Narrowed by the version the build stated, never the row's.
		found, err := unanalyzed(ctx, w.DB.DB, w.Product.ID, 0, "openssl", graph.Choice{Version: "3.0.11-1"})
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].BuildID != w.Build.ID {
			t.Errorf("typed with the version the build stated, the builds never analyzed are %+v", found)
		}
	})
}
