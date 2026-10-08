// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// AdvisoryOver mints an advisory, names one issue in one product on it, and
// answers the identifier it was minted under.
//
// Two requests where there used to be none: an advisory is a record of its own
// now, so what a document is about is stated rather than read off the path.
func AdvisoryOver(t *testing.T, r *Reach, who, product, identifier string) string {
	t.Helper()
	made := AsPerson(t, r, who, http.MethodPost, "/v1/advisories", `{}`)
	if made.Code != http.StatusCreated {
		t.Fatalf("starting an advisory answered %d: %s", made.Code, made.Body.String())
	}
	var started struct {
		Advisory string `json:"advisory"`
	}
	if err := json.Unmarshal(made.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	added := AsPerson(t, r, who, http.MethodPost,
		"/v1/advisories/"+started.Advisory+"/issues",
		`{"product":"`+product+`","vulnerability":"`+identifier+`"}`)
	if added.Code != http.StatusCreated {
		t.Fatalf("adding %s answered %d: %s", identifier, added.Code, added.Body.String())
	}
	return started.Advisory
}

// Advised uploads one CSAF security advisory.
func (r *Reach) Advised(t *testing.T, who, filename, document string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("advisory", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(document)); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/products/mine/supplier-advisories", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set(TestHeader, who)
	FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return rec
}

// SupplierAdvisory is a conforming CSAF security advisory about one package at
// one version, in the shape a distribution publishes: the package defined in a
// branch, the platform in another, and the claim pointing at the composite the
// relationship between them makes.
func SupplierAdvisory(identifier, status, version string) string {
	return `{
	  "document": {
	    "category": "csaf_security_advisory", "csaf_version": "2.0",
	    "publisher": {"category": "vendor", "name": "Example Distribution",
	                  "namespace": "https://example.test"},
	    "title": "Example Security Advisory: libnl update",
	    "tracking": {"id": "` + identifier + `", "version": "1", "status": "final",
	                 "initial_release_date": "2026-09-01T00:00:00Z",
	                 "current_release_date": "2026-09-01T00:00:00Z",
	                 "revision_history": [{"number": "1", "date": "2026-09-01T00:00:00Z",
	                                       "summary": "First"}]}
	  },
	  "product_tree": {
	    "branches": [{"category": "vendor", "name": "Example", "branches": [
	      {"category": "product_name", "name": "Example Platform",
	       "product": {"name": "Example Platform", "product_id": "PLATFORM"}},
	      {"category": "architecture", "name": "x86_64", "branches": [
	        {"category": "product_version", "name": "libnl-3-200 ` + version + `",
	         "product": {"name": "libnl-3-200 ` + version + `", "product_id": "PKG",
	           "product_identification_helper": {
	             "purl": "pkg:deb/debian/libnl-3-200@` + version + `"}}}]}]}],
	    "relationships": [{"category": "default_component_of",
	      "full_product_name": {"name": "libnl-3-200 in Example Platform",
	                            "product_id": "PLATFORM:PKG"},
	      "product_reference": "PKG", "relates_to_product_reference": "PLATFORM"}]
	  },
	  "vulnerabilities": [{"cve": "CVE-2026-9999",
	    "product_status": {"` + status + `": ["PLATFORM:PKG"]},
	    "remediations": [{"category": "vendor_fix",
	      "details": "Upgrade to libnl-3-200 ` + version + `.",
	      "product_ids": ["PLATFORM:PKG"]}]}]
	}`
}

// saidOnTheFinding is what publishers have said, as the finding shows it.
type saidOnTheFinding struct {
	Said []struct {
		Publisher  string `json:"publisher"`
		Source     string `json:"source"`
		Identifier string `json:"identifier"`
		Status     string `json:"status"`
		About      string `json:"about"`
		Statement  string `json:"statement"`
		Offers     string `json:"offers"`
	} `json:"said"`
	Standing []struct{} `json:"standing"`
}

// WhatPublishersSay reads the seeded finding's evidence.
func (r *Reach) WhatPublishersSay(t *testing.T) saidOnTheFinding {
	t.Helper()
	var detail saidOnTheFinding
	Read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
		"/findings/CVE-2026-9999/components/libnl-3-200", &detail)
	return detail
}

// Named configures a supplier for a product, or asks for one to be withdrawn.
func (r *Reach) Named(t *testing.T, who, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if who != "" {
		req.Header.Set(TestHeader, who)
	}
	FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return rec
}

// supplierRow is one row of the list, as the API returns it.
type supplierRow struct {
	Name    string  `json:"name"`
	URL     string  `json:"url"`
	Tried   *string `json:"tried"`
	Read    *string `json:"read"`
	Because string  `json:"because"`
}

// Suppliers is what the list endpoint answers for a product.
func (r *Reach) Suppliers(t *testing.T, path string) []supplierRow {
	t.Helper()
	rec := r.Named(t, "admin", http.MethodGet, path, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("listing suppliers answered %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []supplierRow `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return body.Items
}

// ScannedAtTwoPlaces is one issue in one component pulled in by two things, so
// the component sits at two places in the build.
//
// The ordinary case — a library is pulled in by several things — and the one a
// fixture with a single place cannot represent: it cannot tell a rule about a
// place from a rule about a component, which is exactly the distinction a
// document with no place granularity turns on.
func (r *Reach) ScannedAtTwoPlaces(t *testing.T) {
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
	scan, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "two-places", BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	first := graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
	second := graph.Described{
		Purl: "pkg:deb/debian/libteam5@1.31", Name: "libteam5", Version: "1.31",
	}
	library := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{first, second, library},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: first}, {Parent: first, Child: library},
			{Parent: product, Child: second}, {Parent: second, Child: library},
		},
	}); err != nil {
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
	// One report, two places: the places come from the graph, and the library
	// hangs off both consumers.
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{
			Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
			Component: library, FixState: finding.NoFix,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// ScannedBeneathAProduct is one issue in one library that curl pulls in
// directly and through libssh, that an app pulls in, and that the build holds
// directly: four places, two of them beneath curl.
//
// The build names its root by the package identifier given, where one is.
func (r *Reach) ScannedBeneathAProduct(t *testing.T, root string) {
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
	scan, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "beneath-a-product", BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if root != "" {
		if _, err := r.DB.DB.NewUpdate().Table("scan").Set("root_identifier = ?", root).
			Where("id = ?", scan.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	curl := graph.Described{Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0"}
	libssh := graph.Described{Purl: "pkg:deb/debian/libssh@0.10.6", Name: "libssh", Version: "0.10.6"}
	app := graph.Described{Purl: "pkg:deb/debian/app@1.0", Name: "app", Version: "1.0"}
	library := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{curl, libssh, app, library},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: curl}, {Parent: curl, Child: library},
			{Parent: curl, Child: libssh}, {Parent: libssh, Child: library},
			{Parent: product, Child: app}, {Parent: app, Child: library},
			{Parent: product, Child: library},
		},
	}); err != nil {
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{
			Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
			Component: library, FixState: finding.NoFix,
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// PatchedKernel is the two-issue build with the first issue patched in the
// kernel, as the build declares it.
func (r *Reach) PatchedKernel(t *testing.T) {
	t.Helper()
	r.ScannedTwoIssuesArguing(t, "patched", []sbom.Suppression{{
		Vulnerability: "CVE-2026-9999", Status: sbom.AlreadyFixed,
		Statement: "resolved by a patch the build carries",
		Targets:   []sbom.Target{{Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image"}},
		Origin:    sbom.FromPedigree,
	}})
}

// FixedIn reads the document and returns what it says is fixed, by issue.
func (r *Reach) FixedIn(t *testing.T) map[string][]string {
	t.Helper()
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status   string `json:"status"`
			Products []struct {
				Subcomponents []struct {
					ID string `json:"@id"`
				} `json:"subcomponents"`
			} `json:"products"`
		} `json:"statements"`
	}
	Read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom/vex", &doc)
	fixed := map[string][]string{}
	for _, one := range doc.Statements {
		if one.Status != "fixed" {
			t.Errorf("%s is said as %q, and nothing here was agreed to", one.Vulnerability.Name, one.Status)
			continue
		}
		for _, product := range one.Products {
			for _, inside := range product.Subcomponents {
				fixed[one.Vulnerability.Name] = append(fixed[one.Vulnerability.Name], inside.ID)
			}
		}
	}
	return fixed
}

// PatchedRows runs a statement against the rows the patch closed.
func (r *Reach) PatchedRows(t *testing.T, statement string) {
	t.Helper()
	if _, err := r.DB.ExecContext(t.Context(), statement); err != nil {
		t.Fatal(err)
	}
}

// VexStatements reads the build's document as issue, status and the
// subcomponent each statement names, in the order the document holds them.
func (r *Reach) VexStatements(t *testing.T) [][3]string {
	t.Helper()
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Status   string `json:"status"`
			Products []struct {
				Subcomponents []struct {
					ID string `json:"@id"`
				} `json:"subcomponents"`
			} `json:"products"`
		} `json:"statements"`
	}
	Read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom/vex", &doc)
	var out [][3]string
	for _, one := range doc.Statements {
		inside := ""
		if len(one.Products) == 1 && len(one.Products[0].Subcomponents) == 1 {
			inside = one.Products[0].Subcomponents[0].ID
		}
		out = append(out, [3]string{one.Vulnerability.Name, one.Status, inside})
	}
	return out
}

// Vexed uploads one OpenVEX document as a publisher's statements.
func (r *Reach) Vexed(t *testing.T, who, publisher, document string) *httptest.ResponseRecorder {
	t.Helper()
	return r.VexedAs(t, who, publisher, publisher+".json", document)
}

// VexedAs uploads a VEX document under a chosen file name, naming the
// publisher in the query only where one is given.
func (r *Reach) VexedAs(t *testing.T, who, publisher, filename, document string) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("statements", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte(document)); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	at := "/v1/products/mine/vex-statements"
	if publisher != "" {
		at += "?publisher=" + publisher
	}
	req := httptest.NewRequest(http.MethodPost, at, &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set(TestHeader, who)
	FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return rec
}

// Said is a conforming OpenVEX document making one statement.
func Said(status, justification, statement string) string {
	return `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1",
		"author":"Example Distribution","timestamp":"2026-09-01T00:00:00Z","version":1,
		"statements":[{"vulnerability":{"name":"CVE-2026-9999"},
		"products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0"}],
		"status":"` + status + `"` +
		func() string {
			out := ""
			if justification != "" {
				out += `,"justification":"` + justification + `"`
			}
			if statement != "" {
				// The format's own field names: a reason under not_affected is
				// an impact statement, and one under affected is an action
				// statement. There is no bare "statement".
				if status == "affected" {
					out += `,"action_statement":"` + statement + `"`
				} else {
					out += `,"impact_statement":"` + statement + `"`
				}
			}
			return out
		}() + `}]}`
}

// Alerts is what somebody has been told, of one kind.
func (r *Reach) Alerts(t *testing.T, who, kind string) []string {
	t.Helper()
	// Driven directly: the sweep is a background pass rather than a route, so
	// there is nothing to ask for it over HTTP.
	if _, _, err := notify.NewWatch(r.DB.DB,
		slog.New(slog.NewTextHandler(io.Discard, nil))).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	var waiting struct {
		Items []struct {
			Kind string `json:"kind"`
			Body string `json:"body"`
		} `json:"items"`
	}
	Read(t, r, who, "/v1/notifications", &waiting)
	var about []string
	for _, one := range waiting.Items {
		if one.Kind == kind {
			about = append(about, one.Body)
		}
	}
	return about
}

const ABuild = "/v1/products/mine/streams/master/variants/broadcom/vex"

// RecordedIssuance records that the document for the build went out and
// answers with what was recorded.
func RecordedIssuance(t *testing.T, r *Reach, who string) struct {
	Version int    `json:"version"`
	Digest  string `json:"digest"`
} {
	t.Helper()
	var recorded struct {
		Version int    `json:"version"`
		Digest  string `json:"digest"`
	}
	got := AsPerson(t, r, who, http.MethodPost, ABuild+"/issuance", "")
	if got.Code != http.StatusCreated {
		t.Fatalf("recording that it went out answered %d: %s", got.Code, got.Body.String())
	}
	if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	return recorded
}

// Alias records or removes another name for an issue, answering the status.
func (r *Reach) Alias(t *testing.T, method, issue, name string) int {
	t.Helper()
	got := AsPerson(t, r, "private-triage", method,
		fmt.Sprintf("/v1/products/mine/issues/%s/aliases/%s", issue, name), "")
	return got.Code
}
