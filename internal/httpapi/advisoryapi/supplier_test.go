// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const build = "/v1/products/mine/streams/master/variants/broadcom"

// statementsAbout reads one kind of the build's document, as its identifier
// and what it says about CVE-2022-37434.
func statementsAbout(t *testing.T, r *httpapitest.Reach, kind string) (string, []vexSaid) {
	t.Helper()
	var doc struct {
		ID         string    `json:"@id"`
		Statements []vexSaid `json:"statements"`
	}
	at := build + "/vex"
	if kind != "" {
		at += "?kind=" + kind
	}
	httpapitest.Read(t, r, "triager", at, &doc)
	var about []vexSaid
	for _, one := range doc.Statements {
		if one.Vulnerability.Name == "CVE-2022-37434" {
			about = append(about, one)
		}
	}
	return doc.ID, about
}

type vexSaid struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Status          string `json:"status"`
	Justification   string `json:"justification"`
	ImpactStatement string `json:"impact_statement"`
}

// A supplier's statement about its own product, uploaded through the ordinary
// route, closes the finding inside the product. The register lists the closure
// with the supplier's words, and the build's document says it only where asked
// to carry suppliers' statements, under an identifier of its own.
func TestASuppliersStatementClosesTheFindingAndIsPublishedOnlyWhenAsked(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if got := r.VexedAs(t, "admin", "acme", "acme-y.openvex.json", httpapitest.AcmeSays(t)); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		r.ScannedInsideAcme(t, "inside", false)

		var register struct {
			Items []struct {
				ClosedBecause string `json:"closed_because"`
				Stated        *struct {
					Publisher string `json:"publisher"`
					Product   string `json:"product"`
					Statement string `json:"statement"`
				} `json:"stated"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", build+"/register?closed_because=disclaimed", &register)
		if len(register.Items) != 1 || register.Items[0].Stated == nil ||
			register.Items[0].Stated.Product != "acme-y" {
			t.Fatalf("the register lists %+v closed by a supplier", register.Items)
		}

		ours, said := statementsAbout(t, r, "")
		if len(said) != 0 {
			t.Errorf("this deployment's own document says %+v; nobody here agreed to it", said)
		}
		with, said := statementsAbout(t, r, "with-suppliers")
		if with == ours || !strings.HasSuffix(with, "/with-suppliers") {
			t.Errorf("the document with suppliers is called %q, and ours %q", with, ours)
		}
		if len(said) != 1 || said[0].Status != "not_affected" ||
			said[0].Justification != "vulnerable_code_not_in_execute_path" ||
			!strings.Contains(said[0].ImpactStatement, "Per acme, in acme-y.openvex.json") ||
			!strings.Contains(said[0].ImpactStatement, "inflateGetHeader") {
			t.Errorf("the document with suppliers says %+v", said)
		}

		// Each kind counts its own revisions.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			build+"/vex/issuance?kind=with-suppliers", ""); got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}
		var gone struct {
			Items []struct {
				Version int `json:"version"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", build+"/vex/issuance", &gone)
		if len(gone.Items) != 0 {
			t.Errorf("recording the document with suppliers recorded %d of ours", len(gone.Items))
		}
		httpapitest.Read(t, r, "triager", build+"/vex/issuance?kind=with-suppliers", &gone)
		if len(gone.Items) != 1 || gone.Items[0].Version != 1 {
			t.Errorf("the document with suppliers went out as %+v, want its first revision", gone.Items)
		}

		// The same zlib pulled in outside Y as well: one place of it is open,
		// so the document says nothing about it.
		r.ScannedInsideAcme(t, "outside-too", true)
		if _, said := statementsAbout(t, r, "with-suppliers"); len(said) != 0 {
			t.Errorf("with zlib open under curl, the document says %+v", said)
		}
	})
}
