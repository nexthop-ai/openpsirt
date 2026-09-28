// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// scannedTag declares a tag of "mine" built as broadcom and scans it holding
// the seeded library at a version of its own, with the seeded issue against it.
func (r *reach) scannedTag(t *testing.T, tag, version string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.db.DB)
	product, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := names.DeclareStream(ctx, product.ID, tag, catalog.Tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	variant, err := names.VariantByName(ctx, product.ID, "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, stream.ID, variant.ID)
	if err != nil {
		t.Fatal(err)
	}
	made, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "tag-" + tag, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	lib := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@" + version, Name: "libnl-3-200", Version: version,
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, made.ID, graph.Snapshot{
		Root: seededRoot, Components: []graph.Described{lib},
		Dependencies: []graph.Dependency{{Parent: seededRoot, Child: lib}},
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{{
		Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
		Component: lib, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
	}}); err != nil {
		t.Fatal(err)
	}
}

// Carrying writes the chosen judgment onto the new line as a claim waiting for
// agreement, from the line named in the query to the one in the path, and only
// for somebody who may decide there.
func TestCarryingWritesClaimsWaitingForASecondPerson(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		decision, claim := r.decidedAt(t, place)
		r.agreed(t, claim)
		r.scannedTag(t, "v2.0", "3.7.1")

		const at = "/v1/products/mine/streams/v2.0/variants/broadcom/carried" +
			"?from=master&from_variant=broadcom"
		var offered struct {
			Moved []struct {
				Decision int64 `json:"decision"`
			} `json:"moved"`
		}
		read(t, r, "triager", at, &offered)
		if len(offered.Moved) != 1 || offered.Moved[0].Decision != decision {
			t.Fatalf("the tag was offered %+v, want the one judgment whose version moved", offered)
		}

		carry := func(who string, ids ...int64) *httptest.ResponseRecorder {
			body, err := json.Marshal(map[string][]int64{"decisions": ids})
			if err != nil {
				t.Fatal(err)
			}
			return asPerson(t, r, who, http.MethodPost, at, string(body))
		}
		refusedWith(t, carry("outsider", decision), http.StatusNotFound)
		refusedWith(t, carry("reader", decision), http.StatusNotFound)
		refusedWith(t, carry("triager", decision+1000), http.StatusUnprocessableEntity)

		got := carry("triager", decision)
		if got.Code != http.StatusCreated {
			t.Fatalf("carrying answered %d: %s", got.Code, got.Body.String())
		}
		var carried struct {
			Carried int `json:"carried"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &carried); err != nil {
			t.Fatal(err)
		}
		if carried.Carried != 1 {
			t.Errorf("carried %d, want 1", carried.Carried)
		}

		// The claim waits on the tag's version, which is where the path put it.
		var waiting struct {
			Items []struct {
				Finding *struct {
					Stream  string `json:"stream"`
					Version string `json:"version"`
				} `json:"finding"`
			} `json:"items"`
		}
		read(t, r, "reviewer", "/v1/review-queue", &waiting)
		if len(waiting.Items) != 1 || waiting.Items[0].Finding == nil ||
			waiting.Items[0].Finding.Stream != "v2.0" || waiting.Items[0].Finding.Version != "3.7.1" {
			t.Errorf("the review queue holds %+v, want one claim waiting on the tag", waiting.Items)
		}
	})
}
