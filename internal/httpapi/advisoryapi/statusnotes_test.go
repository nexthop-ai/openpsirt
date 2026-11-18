// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/advisoryapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// notedSays is a statement's status notes as a document writes them: markup
// a renderer would act on, so a reader seeing it as written shows it was
// never rendered.
const notedSays = "Confirmed by a code audit, <b>2026-09</b>"

// A supplier's status notes are shown with its statement on the finding, and
// published in its name on the statement the document with suppliers makes
// from it.
func TestASuppliersStatusNotesAreShownAndPublishedInItsName(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		const impact = `"impact_statement": "Acme Y never calls inflateGetHeader()."`
		said := strings.Replace(httpapitest.AcmeSays(t), impact,
			impact+`, "status_notes": "`+strings.ReplaceAll(notedSays, `"`, `\"`)+`"`, 1)
		if said == httpapitest.AcmeSays(t) {
			t.Fatal("the supplier's document has no impact statement to write notes beside")
		}
		if got := r.VexedAs(t, "admin", "acme", "acme-y.openvex.json", said); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		r.ScannedInsideAcme(t, "inside", false)

		var detail struct {
			Said []struct {
				Status    string `json:"status"`
				Statement string `json:"statement"`
				Notes     string `json:"notes"`
			} `json:"said"`
		}
		httpapitest.Read(t, r, "triager", build+"/findings/CVE-2022-37434/components/zlib", &detail)
		if len(detail.Said) != 1 || detail.Said[0].Notes != notedSays ||
			detail.Said[0].Statement != "Acme Y never calls inflateGetHeader()." {
			t.Errorf("the finding shows %+v, want the supplier's words and its notes as written", detail.Said)
		}

		// The register states the closing statement with its notes, in the
		// list and in the file.
		var register struct {
			Items []struct {
				Stated *struct {
					Notes string `json:"notes"`
				} `json:"stated"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", build+"/register?closed_because=disclaimed", &register)
		if len(register.Items) != 1 || register.Items[0].Stated == nil ||
			register.Items[0].Stated.Notes != notedSays {
			t.Errorf("the register lists %+v, want the closing statement with its notes", register.Items)
		}
		file := httpapitest.AsPerson(t, r, "triager", http.MethodGet, build+"/register.csv", "")
		if file.Code != http.StatusOK || !strings.Contains(file.Body.String(), "Notes: "+notedSays) {
			t.Errorf("the register file answered %d without the notes:\n%s", file.Code, file.Body.String())
		}

		var doc struct {
			Statements []struct {
				Vulnerability struct {
					Name string `json:"name"`
				} `json:"vulnerability"`
				Status      string `json:"status"`
				StatusNotes string `json:"status_notes"`
			} `json:"statements"`
		}
		httpapitest.Read(t, r, "triager", build+"/vex?kind=with-suppliers", &doc)
		stated := 0
		for _, one := range doc.Statements {
			if one.Vulnerability.Name != "CVE-2022-37434" {
				continue
			}
			stated++
			if one.StatusNotes != "Per acme: "+notedSays {
				t.Errorf("the document with suppliers states the notes as %q, want them in acme's name",
					one.StatusNotes)
			}
		}
		if stated != 1 {
			t.Errorf("the document with suppliers makes %d statements about the issue, want one", stated)
		}
	})
}

// A declared patch is stated fixed with the status notes of the build's own
// claim, and the build's claims list them beside the claim. A decision made
// here states no notes.
func TestABuildsStatusNotesAreShownAndPublishedOnItsPatch(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssuesArguing(t, "patched", []sbom.Suppression{{
			Vulnerability: "CVE-2026-9999", Status: sbom.AlreadyFixed, Notes: notedSays,
			Targets: []sbom.Target{{Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image"}},
			Origin:  sbom.FromStatement,
		}})
		decision, _ := r.Claimed(t, "triager", "CVE-2026-1000", "linux-image", httpapitest.Dismissal)
		r.Agreed(t, decision)

		// The finding it closed is not worked, so the claim is read where the
		// build's claims are listed.
		var carried struct {
			Items []struct {
				Status string `json:"status"`
				Notes  string `json:"notes"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", build+"/carried-patches", &carried)
		if len(carried.Items) != 1 || carried.Items[0].Status != "fixed" || carried.Items[0].Notes != notedSays {
			t.Errorf("the build's claims read %+v, want the fixed claim with its notes as written", carried.Items)
		}

		var doc struct {
			Statements []struct {
				Vulnerability struct {
					Name string `json:"name"`
				} `json:"vulnerability"`
				Status      string `json:"status"`
				StatusNotes string `json:"status_notes"`
			} `json:"statements"`
		}
		httpapitest.Read(t, r, "triager", build+"/vex", &doc)
		stated := map[string]string{}
		for _, one := range doc.Statements {
			stated[one.Vulnerability.Name+" "+one.Status] = one.StatusNotes
		}
		if notes, ok := stated["CVE-2026-9999 fixed"]; !ok || notes != notedSays {
			t.Errorf("the document states %v, want the patch fixed with the build's notes", stated)
		}
		if notes, ok := stated["CVE-2026-1000 not_affected"]; !ok || notes != "" {
			t.Errorf("the document states %v, want the dismissal with no notes", stated)
		}
	})
}

// An upstream's status notes are shown with its statement where it is offered
// for review and where a component's upstream statements are listed.
func TestAnUpstreamsStatusNotesAreShownWhereItsStatementIsReviewed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		ctx := t.Context()
		held, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		admin, err := r.Rights.ByIdentity(ctx, "admin")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := finding.NewStore(r.DB.DB).RecordStatements(ctx,
			access.Subject{Kind: access.Person, ID: admin.ID}, held.ID, finding.Supplied{
				Source: finding.FromUpstream, Identifier: "VEX-upstream-mine",
				Publisher: "Example Upstream", Document: "https://upstream.example.test/mine.json",
				Digest: strings.Repeat("b", 64),
			}, []finding.Statement{{
				Vulnerability: "CVE-2026-9999", Purl: "pkg:deb/debian/libnl-3-200@3.7.0",
				Component: "libnl-3-200", About: "3.7.0", Status: "not_affected",
				Justification: "vulnerable_code_not_present", Notes: notedSays,
			}}); err != nil {
			t.Fatal(err)
		}

		var offers struct {
			Items []advisoryapi.OfferBody `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/upstream-offers", &offers)
		if len(offers.Items) != 1 || offers.Items[0].Notes != notedSays {
			t.Errorf("offered %+v, want the upstream's statement with its notes as written", offers.Items)
		}

		var said struct {
			Items []advisoryapi.UpstreamSaidBody `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/components/libnl-3-200/upstream-statements", &said)
		if len(said.Items) != 1 || said.Items[0].Notes != notedSays {
			t.Errorf("the component lists %+v, want the upstream's statement with its notes", said.Items)
		}
	})
}
