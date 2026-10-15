// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
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

// Build names one build of a product by its three names.
type Build struct{ Product, Stream, Variant string }

// SeededBuild is the build every Reach is declared with.
var SeededBuild = Build{Product: "mine", Stream: "master", Variant: "broadcom"}

// The scanner run every seed reports through.
const (
	seededScanner         = "grype"
	seededScannerVersion  = "0.112.0"
	seededDatabaseVersion = "2026-08-28"
)

// TargetOf is the target a build's names resolve to. The names must already
// be declared.
func (r *Reach) TargetOf(t testing.TB, b Build) int64 {
	t.Helper()
	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(t.Context(), b.Product, b.Stream, b.Variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(t.Context(), located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	return target.ID
}

// Recorded records one accepted upload against a target, built now, and
// answers with its scan.
//
// The hash is what tells two uploads of one build apart, so a seed applied
// twice to one build passes a hash of its own each time.
func (r *Reach) Recorded(t testing.TB, target int64, hash string) int64 {
	t.Helper()
	made, outcome, err := ingest.NewStore(r.DB.DB).Record(t.Context(), ingest.Arriving{
		TargetID: target, ContentHash: hash, ParserVersion: "test",
		// Not ahead of the clock: a build stamped in the future is refused,
		// because accepting one means no later scan is ever newer.
		BuiltAt: time.Now().UTC(),
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	return made.ID
}

// Shipped records an upload of a build and applies its graph, with no scanner
// run: what a build holds before anything has been reported against it.
func (r *Reach) Shipped(t testing.TB, b Build, hash string, snapshot graph.Snapshot) (target, scan int64) {
	t.Helper()
	target = r.TargetOf(t, b)
	scan = r.Recorded(t, target, hash)
	if _, err := fixture.ApplyGraph(t.Context(), r.DB.DB, target, scan, snapshot); err != nil {
		t.Fatal(err)
	}
	return target, scan
}

// Argued records what an upload argues about what it ships, with statements
// and pedigree both stated by the build.
func (r *Reach) Argued(t testing.TB, target, scan int64, claims []sbom.Suppression) {
	t.Helper()
	if _, err := fixture.RecordClaims(t.Context(), r.DB.DB, target, scan, claims,
		map[sbom.Origin]bool{sbom.FromStatement: true, sbom.FromPedigree: true}); err != nil {
		t.Fatal(err)
	}
}

// Ran applies one scanner run reporting these findings against a target.
func (r *Reach) Ran(t testing.TB, target int64, reported []finding.Reported) {
	t.Helper()
	findings := finding.NewStore(r.DB.DB)
	run, err := findings.Begin(t.Context(), finding.Run{
		TargetID: target, Scanner: seededScanner, ScannerVersion: seededScannerVersion,
		DatabaseVersion: seededDatabaseVersion, RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Apply(t.Context(), target, run.ID, reported); err != nil {
		t.Fatal(err)
	}
}

// ScanAt ships a build and applies one run reporting these findings against
// it.
func (r *Reach) ScanAt(t testing.TB, b Build, hash string, snapshot graph.Snapshot,
	reported []finding.Reported) (target, scan int64) {

	t.Helper()
	target, scan = r.Shipped(t, b, hash, snapshot)
	r.Ran(t, target, reported)
	return target, scan
}

// Scan is ScanAt on the seeded build. Every test here reads back through the
// API, so it answers with nothing.
func (r *Reach) Scan(t *testing.T, hash string, snapshot graph.Snapshot,
	reported []finding.Reported) {

	t.Helper()
	r.ScanAt(t, SeededBuild, hash, snapshot, reported)
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
	contentType := ""
	if body != "" {
		contentType = "application/json"
	}
	return r.Post(t, who, method, path, strings.NewReader(body), contentType)
}

// Post makes a request with a body of a given type the way a signed-in person
// does. Nobody is named where who is empty, which is a caller who has not
// signed in.
func (r *Reach) Post(t testing.TB, who, method, path string, body io.Reader,
	contentType string) *httptest.ResponseRecorder {

	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if who != "" {
		req.Header.Set(TestHeader, who)
	}
	FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return rec
}

// Part is one part of a multipart form: a file where it has a file name, and a
// plain field where it has none.
type Part struct{ Field, Filename, Content string }

// Form encodes parts as a multipart body, in order, and answers with the body
// and the content type naming its boundary.
func Form(t testing.TB, parts ...Part) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for _, part := range parts {
		if part.Filename == "" {
			if err := form.WriteField(part.Field, part.Content); err != nil {
				t.Fatal(err)
			}
			continue
		}
		file, err := form.CreateFormFile(part.Field, part.Filename)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(file, part.Content); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, form.FormDataContentType()
}

// Itoa is an identifier as a path segment.
func Itoa(n int64) string { return strconv.FormatInt(n, 10) }

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
