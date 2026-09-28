// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// refusedWith pins the status a refusal answers with.
//
// A bound such as `got.Code < 400` also holds for a 404 from a renamed route, a
// 422 for an unrelated body rule, a 403 that says a hidden product exists, and
// the 500 chi's recovery middleware makes of a panic. An exact status rules
// out every failure but the one that shares it: a 404 refusal still needs its
// own sentence checked, or the same path answered successfully beside it, to
// tell it from a route that moved.
func refusedWith(t *testing.T, got *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got.Code != want {
		t.Fatalf("got %d %s, want %d %s: %s", got.Code, http.StatusText(got.Code),
			want, http.StatusText(want), got.Body.String())
	}
}

// scan applies one snapshot and one set of reported findings to the seeded
// build, and answers with nothing: every test here reads back through the API.
//
// The two seeds below differ in the graph they apply and what the report
// carries, and in nothing else — they had a locate, a target lookup, a scan
// record, a run and an apply written out twice between them, which is five
// calls whose failure modes a reader has to check twice to find out they are
// the same.
func (r *reach) scan(t *testing.T, hash string, snapshot graph.Snapshot,
	reported []finding.Reported) {

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
	made, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: hash, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, made.ID, snapshot); err != nil {
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, reported); err != nil {
		t.Fatal(err)
	}
}

// scanned puts a build behind the handler: one component under the product,
// with one issue reported against it. Reading what has been decided is only
// testable against something that was found.
func (r *reach) scanned(t *testing.T) (place string) {
	t.Helper()
	r.scan(t, "read-test",
		graph.Snapshot{
			Root:         seededRoot,
			Components:   []graph.Described{seededLib},
			Dependencies: []graph.Dependency{{Parent: seededRoot, Child: seededLib}},
		},
		[]finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
			Component: seededLib,
			FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
		}})

	// Under the product itself, the component stands alone.
	return finding.PlaceIdentity("libnl-3-200", "")
}

// scannedWithEvidence is a build whose one finding carries everything a report
// can carry, so a test can ask whether any of it survives the trip.
func (r *reach) scannedWithEvidence(t *testing.T) {
	t.Helper()
	r.scan(t, "evidence-test",
		graph.Snapshot{
			Root:       seededRoot,
			Components: []graph.Described{seededConsumer, seededLib},
			Dependencies: []graph.Dependency{
				{Parent: seededRoot, Child: seededConsumer},
				{Parent: seededConsumer, Child: seededLib},
			},
		},
		[]finding.Reported{{
			Issue: finding.Named{
				Identifier:  "CVE-2026-9999",
				Severity:    "high",
				Description: "A crafted attribute length causes a read past the end of the buffer.",
				Advisory:    "https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
				References: []finding.Reference{
					{URL: "https://github.com/thom311/libnl/commit/abc123", Kind: finding.Patch},
					{URL: "https://example.org/write-up", Kind: finding.AdvisoryRef},
				},
				Exploited:  true,
				Likelihood: 0.86,
				Score:      8.1,
				Vector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H",
				Weaknesses: []string{"CWE-125"},
			},
			Component: seededLib,
			FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
		}})
}

// decided proposes a claim through the API and returns its identifier.
func (r *reach) decided(t *testing.T, place string) int64 {
	t.Helper()
	id, _ := r.decidedAt(t, place)
	return id
}

// decidedAt records one judgment and answers with the row it wrote and the
// claim it belongs to. What the judgment says — and so what may be revised,
// agreed to, commented on or withdrawn — is the claim's.
func (r *reach) decidedAt(t *testing.T, place string) (decision, claim int64) {
	t.Helper()
	path := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
		"/findings/CVE-2026-9999/places/%s/decision", place)
	got := asPerson(t, r, "triager", http.MethodPost, path,
		`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
			`"reasoning":"The parser is never reached: we only call the encoder."}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("proposing answered %d: %s", got.Code, got.Body.String())
	}
	var out struct {
		ID      int64 `json:"id"`
		ClaimID int64 `json:"claim_id"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, got.Body.String())
	}
	if out.ClaimID == 0 {
		t.Fatalf("a judgment came back without the claim it made: %s", got.Body.String())
	}
	return out.ID, out.ClaimID
}

// read makes a GET as somebody and decodes what came back.
func read(t *testing.T, r *reach, who, path string, into any) {
	t.Helper()
	got := asPerson(t, r, who, http.MethodGet, path, "")
	if got.Code != http.StatusOK {
		t.Fatalf("GET %s answered %d: %s", path, got.Code, got.Body.String())
	}
	if err := json.Unmarshal(got.Body.Bytes(), into); err != nil {
		t.Fatalf("decode %s: %v (%s)", path, err, got.Body.String())
	}
}
