// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// scannedShared is a build where one library sits under two containers and
// carries two issues: the shape a tree count has to answer per path.
func (r *reach) scannedShared(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.db.DB)
	located, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "shared", BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	a := graph.Described{Purl: "pkg:oci/docker-a@1", Name: "docker-a", Version: "1"}
	b := graph.Described{Purl: "pkg:oci/docker-b@1", Name: "docker-b", Version: "1"}
	lib := graph.Described{Purl: "pkg:deb/debian/libyang@2.1", Name: "libyang", Version: "2.1"}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{a, b, lib},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: a}, {Parent: product, Child: b},
			{Parent: a, Child: lib}, {Parent: b, Child: lib},
		},
	}); err != nil {
		t.Fatal(err)
	}
	findings := finding.NewStore(r.db.DB)
	run, err := findings.Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", ScannerVersion: "0.112.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{Issue: finding.Named{Identifier: "CVE-2026-1", Severity: "high"}, Component: lib, FixState: finding.NoFix},
		{Issue: finding.Named{Identifier: "CVE-2026-2", Severity: "low"}, Component: lib, FixState: finding.NoFix},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestATreeCountIsPerPathAndTheListItOpensAgrees(t *testing.T) {
	// A library at two places with two issues reads four under every parent
	// where the count is per finding, because a finding is one issue at one
	// place. Somebody who drilled down one path is looking at one place and
	// expects two — and the list the number opens has to show the same.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedShared(t)
		const build = "/v1/products/mine/streams/master/variants/broadcom"

		type node struct {
			Component string `json:"component"`
			Findings  int    `json:"findings"`
			Beneath   int    `json:"beneath"`
		}
		around := func(name string) (above, below []node) {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodGet, build+"/components/"+name+"/around", "")
			if got.Code != http.StatusOK {
				t.Fatalf("around %s answered %d: %s", name, got.Code, got.Body.String())
			}
			var out struct {
				Above []node `json:"above"`
				Below []node `json:"below"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			return out.Above, out.Below
		}
		for _, parent := range []string{"docker-a", "docker-b"} {
			_, below := around(parent)
			if len(below) != 1 || below[0].Component != "libyang" {
				t.Fatalf("under %s: %+v", parent, below)
			}
			if below[0].Findings != 2 || below[0].Beneath != 2 {
				t.Errorf("libyang under %s reads %d findings, %d beneath; want 2 and 2", parent, below[0].Findings, below[0].Beneath)
			}
		}
		// The root counts distinct issues open in the build.
		got := asPerson(t, r, "triager", http.MethodGet, build+"/components", "")
		var roots struct {
			Root  *node  `json:"root"`
			Items []node `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &roots); err != nil || roots.Root == nil {
			t.Fatalf("the roots read as %s (%v)", got.Body.String(), err)
		}
		if roots.Root.Beneath != 2 {
			t.Errorf("the root reads %d beneath, want the 2 distinct issues", roots.Root.Beneath)
		}
		for _, item := range roots.Items {
			if item.Beneath != 2 {
				t.Errorf("%s reads %d beneath, want 2", item.Component, item.Beneath)
			}
		}

		// The list the number opens: two rows, one per issue and
		// component. The list is scoped by query rather than by path:
		// with the branch and the variant named it is this one build.
		const listing = "/v1/products/mine/findings?stream=master&variant=broadcom"
		list := func(query string) (total int, code int) {
			t.Helper()
			got := asPerson(t, r, "triager", http.MethodGet, listing+query, "")
			var out struct {
				Total int `json:"total"`
			}
			_ = json.Unmarshal(got.Body.Bytes(), &out)
			return out.Total, got.Code
		}
		if total, code := list("&beneath=docker-a"); code != http.StatusOK || total != 2 {
			t.Errorf("beneath docker-a answered %d with %d rows, want 2", code, total)
		}
		if total, code := list("&beneath=libyang"); code != http.StatusOK || total != 2 {
			t.Errorf("beneath libyang answered %d with %d rows, want 2", code, total)
		}
		if total, code := list("&beneath=mine"); code != http.StatusOK || total != 2 {
			t.Errorf("beneath the root answered %d with %d rows, want 2", code, total)
		}
		// under is still the direct consumer, and beneath refuses a name the
		// build does not hold.
		if total, code := list("&under=docker-a"); code != http.StatusOK || total != 2 {
			t.Errorf("under docker-a answered %d with %d rows, want 2", code, total)
		}
		if _, code := list("&beneath=nothing-here"); code != http.StatusUnprocessableEntity {
			t.Errorf("beneath a name the build lacks answered %d, want 422", code)
		}
		got = asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings/components?stream=master&variant=broadcom&beneath=docker-b", "")
		var byComponent struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &byComponent); err != nil || got.Code != http.StatusOK || byComponent.Total != 1 {
			t.Errorf("by component beneath docker-b answered %d with %d components, want 1", got.Code, byComponent.Total)
		}
	})
}

func TestTheTreeIsReachedByNameAndVersionWhereANameIsNotEnough(t *testing.T) {
	// A build ships one name at several versions, and arriving from a finding
	// at one of them had no way to say which — the reader saw an error
	// instead of the tree.
	eachReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		names := catalog.NewStore(r.db.DB)
		located, err := names.Locate(ctx, "mine", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
		if err != nil {
			t.Fatal(err)
		}
		scan, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "versions", BuiltAt: time.Now().UTC(), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}
		product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
		old := graph.Described{Purl: "pkg:golang/stdlib@go1.24.9", Name: "stdlib", Version: "go1.24.9"}
		newer := graph.Described{Purl: "pkg:golang/stdlib@go1.25.6", Name: "stdlib", Version: "go1.25.6"}
		if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
			Root:       product,
			Components: []graph.Described{old, newer},
			Dependencies: []graph.Dependency{
				{Parent: product, Child: old}, {Parent: product, Child: newer},
			},
		}); err != nil {
			t.Fatal(err)
		}

		const at = "/v1/products/mine/streams/master/variants/broadcom/components/stdlib/around"
		got := asPerson(t, r, "triager", http.MethodGet, at, "")
		if got.Code != http.StatusConflict {
			t.Errorf("a name the build holds at two versions answered %d, want 409: %s", got.Code, got.Body.String())
		}
		got = asPerson(t, r, "triager", http.MethodGet, at+"?version=go1.25.6", "")
		if got.Code != http.StatusOK {
			t.Fatalf("naming the version answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Above []struct {
				Component string `json:"component"`
			} `json:"above"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || len(out.Above) != 1 || out.Above[0].Component != "mine" {
			t.Errorf("the tree around stdlib go1.25.6 reads as %s (%v)", got.Body.String(), err)
		}
		got = asPerson(t, r, "triager", http.MethodGet, at+"?version=go1.0.0", "")
		if got.Code != http.StatusNotFound {
			t.Errorf("a version the build lacks answered %d, want 404", got.Code)
		}
	})
}
