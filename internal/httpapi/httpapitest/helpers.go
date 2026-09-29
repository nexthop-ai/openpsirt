// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// RefusedWith pins the status a refusal answers with.
//
// A bound such as `got.Code < 400` also holds for a 404 from a renamed route, a
// 422 for an unrelated body rule, a 403 that says a hidden product exists, and
// the 500 chi's recovery middleware makes of a panic. An exact status rules
// out every failure but the one that shares it: a 404 refusal still needs its
// own sentence checked, or the same path answered successfully beside it, to
// tell it from a route that moved.
func RefusedWith(t *testing.T, got *httptest.ResponseRecorder, want int) {
	t.Helper()
	if got.Code != want {
		t.Fatalf("got %d %s, want %d %s: %s", got.Code, http.StatusText(got.Code),
			want, http.StatusText(want), got.Body.String())
	}
}

// Scan applies one snapshot and one set of reported findings to the seeded
// build, and answers with nothing: every test here reads back through the API.
//
// The two seeds below differ in the graph they apply and what the report
// carries, and in nothing else — they had a locate, a target lookup, a scan
// record, a run and an apply written out twice between them, which is five
// calls whose failure modes a reader has to check twice to find out they are
// the same.
func (r *Reach) Scan(t *testing.T, hash string, snapshot graph.Snapshot,
	reported []finding.Reported) {

	t.Helper()
	ctx := t.Context()

	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	made, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: hash, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, made.ID, snapshot); err != nil {
		t.Fatal(err)
	}
	findings := finding.NewStore(r.DB.DB)
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

// Scanned puts a build behind the handler: one component under the product,
// with one issue reported against it. Reading what has been decided is only
// testable against something that was found.
func (r *Reach) Scanned(t *testing.T) (place string) {
	t.Helper()
	r.Scan(t, "read-test",
		graph.Snapshot{
			Root:         SeededRoot,
			Components:   []graph.Described{SeededLib},
			Dependencies: []graph.Dependency{{Parent: SeededRoot, Child: SeededLib}},
		},
		[]finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
			Component: SeededLib,
			FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
		}})

	// Under the product itself, the component stands alone.
	return finding.PlaceIdentity("libnl-3-200", "")
}

// ScannedWithEvidence is a build whose one finding carries everything a report
// can carry, so a test can ask whether any of it survives the trip.
func (r *Reach) ScannedWithEvidence(t *testing.T) {
	t.Helper()
	r.Scan(t, "evidence-test",
		graph.Snapshot{
			Root:       SeededRoot,
			Components: []graph.Described{SeededConsumer, SeededLib},
			Dependencies: []graph.Dependency{
				{Parent: SeededRoot, Child: SeededConsumer},
				{Parent: SeededConsumer, Child: SeededLib},
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
			Component: SeededLib,
			FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
		}})
}

// Decided proposes a claim through the API and returns its identifier.
func (r *Reach) Decided(t *testing.T, place string) int64 {
	t.Helper()
	id, _ := r.DecidedAt(t, place)
	return id
}

// DecidedAt records one judgment and answers with the row it wrote and the
// claim it belongs to. What the judgment says — and so what may be revised,
// agreed to, commented on or withdrawn — is the claim's.
func (r *Reach) DecidedAt(t *testing.T, place string) (decision, claim int64) {
	t.Helper()
	path := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
		"/findings/CVE-2026-9999/places/%s/decision", place)
	got := AsPerson(t, r, "triager", http.MethodPost, path,
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

// Read makes a GET as somebody and decodes what came back.
func Read(t *testing.T, r *Reach, who, path string, into any) {
	t.Helper()
	got := AsPerson(t, r, who, http.MethodGet, path, "")
	if got.Code != http.StatusOK {
		t.Fatalf("GET %s answered %d: %s", path, got.Code, got.Body.String())
	}
	if err := json.Unmarshal(got.Body.Bytes(), into); err != nil {
		t.Fatalf("decode %s: %v (%s)", path, err, got.Body.String())
	}
}

// AsPerson makes a request the way a signed-in person does.
func AsPerson(t *testing.T, r *Reach, who, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(TestHeader, who)
	FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return rec
}

func Itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

// IndexOf is where a column sits, or -1.
//
// Used in place of a fixed position so that adding a column does not quietly
// move an assertion onto its neighbor.
func IndexOf(row []string, name string) int {
	for i, each := range row {
		if each == name {
			return i
		}
	}
	return -1
}

// RowsUnder is the header and the rows, with what the file says about itself
// taken off.
func RowsUnder(rows [][]string) [][]string {
	for i, row := range rows {
		if len(row) == 0 || !strings.HasPrefix(row[0], "# ") {
			return rows[i:]
		}
	}
	return nil
}

// Changed is the trail as an administrator reads it.
type Changed struct {
	Items []struct {
		By      string `json:"by"`
		Kind    string `json:"kind"`
		About   string `json:"about"`
		Was     string `json:"was"`
		Became  string `json:"became"`
		Unset   bool   `json:"unset"`
		Cleared bool   `json:"cleared"`
	} `json:"items"`
	Total int `json:"total"`
}
