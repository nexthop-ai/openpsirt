// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// documents is a page of the uploads of one kind of document.
type documents struct {
	Items []struct {
		ReceivedAt string `json:"received_at"`
		Status     string `json:"status"`
		Reason     string `json:"reason"`
		Publisher  string `json:"publisher"`
		Identifier string `json:"identifier"`
		Document   string `json:"document"`
		Digest     string `json:"digest"`
		UploadedBy string `json:"uploaded_by"`
		FetchedBy  string `json:"fetched_by"`
		Recorded   int    `json:"recorded"`
		SetAside   int    `json:"set_aside"`
		Current    bool   `json:"current"`
	} `json:"items"`
	Total int `json:"total"`
}

func TestEveryUploadOfADocumentIsListedWithWhoSentItAndWhatBecameOfIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		// One publisher's statement set, uploaded twice with a different
		// claim: the second sets the first aside.
		for _, said := range []string{
			httpapitest.Said("affected", "", "Upgrade."),
			httpapitest.Said("not_affected", "vulnerable_code_not_present", "Not built."),
		} {
			if got := r.Vexed(t, "admin", "debian", said); got.Code != http.StatusCreated {
				t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
			}
		}
		httpapitest.RefusedWith(t, r.VexedAs(t, "admin", "", "broken.json", "{"), http.StatusUnprocessableEntity)
		if got := r.Advised(t, "admin", "dsa-1.json",
			httpapitest.SupplierAdvisory("DSA-1", "known_not_affected", "3.7.0")); got.Code != http.StatusCreated {
			t.Fatalf("uploading an advisory answered %d: %s", got.Code, got.Body.String())
		}

		var vex documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/vex-documents", &vex)
		if vex.Total != 3 || len(vex.Items) != 3 {
			t.Fatalf("the VEX list holds %d of %d; want every upload: %+v", len(vex.Items), vex.Total, vex.Items)
		}
		// The newest first.
		refused, second, first := vex.Items[0], vex.Items[1], vex.Items[2]
		if refused.Status != "refused" || refused.Reason == "" || refused.Document != "broken.json" ||
			refused.Current || refused.Digest != "" {
			t.Errorf("the refusal reads %+v", refused)
		}
		if second.Status != "completed" || !second.Current || second.Publisher != "debian" ||
			second.Recorded != 1 || second.SetAside != 1 || second.Digest == "" || second.Reason != "" {
			t.Errorf("debian's second upload reads %+v; want it standing, having set the first aside", second)
		}
		if first.Current || first.SetAside != 0 {
			t.Errorf("debian's first upload reads %+v; want it replaced", first)
		}
		for _, each := range vex.Items {
			if each.UploadedBy != "admin" || each.FetchedBy != "" {
				t.Errorf("%q reads as uploaded by %q and fetched by %q", each.Document, each.UploadedBy, each.FetchedBy)
			}
			if first.ReceivedAt > each.ReceivedAt {
				t.Errorf("%q arrived at %s, before the first at %s", each.Document, each.ReceivedAt, first.ReceivedAt)
			}
		}

		// An advisory is its own kind and never appears among the VEX
		// documents, nor a VEX document among the advisories.
		var advisories documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/supplier-advisories", &advisories)
		if advisories.Total != 1 || len(advisories.Items) != 1 {
			t.Fatalf("the advisory list holds %+v; want DSA-1 alone", advisories.Items)
		}
		if one := advisories.Items[0]; one.Identifier != "DSA-1" || one.Document != "dsa-1.json" ||
			one.Recorded != 1 || !one.Current || one.UploadedBy != "admin" {
			t.Errorf("the advisory reads %+v", one)
		}

		// A page is a page of uploads, and the total is of all of them.
		var page documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/vex-documents?limit=1&offset=1", &page)
		if page.Total != 3 || len(page.Items) != 1 || page.Items[0].ReceivedAt != second.ReceivedAt {
			t.Errorf("the second page of one reads %+v of %d; want debian's second upload", page.Items, page.Total)
		}

		// Another product holds none of them.
		var theirs documents
		httpapitest.Read(t, r, "admin", "/v1/products/theirs/vex-documents", &theirs)
		if theirs.Total != 0 || len(theirs.Items) != 0 {
			t.Errorf("the other product lists %+v", theirs.Items)
		}
	})
}

func TestTheDocumentsUploadedToAProductAreReadByWhoSeesIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		if got := r.Vexed(t, "admin", "debian", httpapitest.Said("fixed", "", "")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		for _, path := range []string{
			"/v1/products/mine/vex-documents", "/v1/products/mine/supplier-advisories",
		} {
			for who, want := range map[string]int{
				"reader": http.StatusOK, "security-testing-reader": http.StatusOK, "admin": http.StatusOK,
				// Somebody who may not know the product exists is told it
				// does not, the same as for a product nobody declared.
				"outsider": http.StatusNotFound, "approver": http.StatusNotFound,
			} {
				if got := r.As(t, who, http.MethodGet, path); got != want {
					t.Errorf("%s reading %s answered %d, want %d", who, path, got, want)
				}
			}
			// A pipeline key sends inventories and reads nothing of these.
			if got := r.AsKey(t, http.MethodGet, path); got != http.StatusForbidden {
				t.Errorf("the key reading %s answered %d, want 403", path, got)
			}
		}
	})
}

func TestAnUploadTurnedAwayAnywhereItCanBeIsListedAsRefused(t *testing.T) {
	const most = 4096
	small := func(d *core.Deps) { d.Limits = sbom.Limits{MaxBytes: most} }
	httpapitest.ReachAdjusted(t, httpapitest.CastSeed.Each, small, func(t *testing.T, r *httpapitest.Reach) {
		said := httpapitest.Said("fixed", "", "")
		// Refused by the form bound, before the operation reads any of it.
		if got := r.Vexed(t, "admin", "debian", said+strings.Repeat(" ", 2<<20)); got.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("a request past the bound answered %d: %s", got.Code, got.Body.String())
		}
		// Refused once it was read, under a publisher too long to record:
		// the file name, where the request names none.
		if got := r.VexedAs(t, "admin", "", strings.Repeat("p", 200)+".json", said); got.Code != http.StatusUnprocessableEntity {
			t.Fatalf("a publisher too long answered %d: %s", got.Code, got.Body.String())
		}
		// Somebody who may not upload is refused before anything is
		// recorded about a document.
		if got := r.Vexed(t, "reader", "debian", said); got.Code != http.StatusForbidden {
			t.Fatalf("a reader uploading answered %d", got.Code)
		}

		var vex documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/vex-documents", &vex)
		if vex.Total != 2 || len(vex.Items) != 2 {
			t.Fatalf("the VEX list holds %+v; want the two refusals", vex.Items)
		}
		long, bounded := vex.Items[0], vex.Items[1]
		if long.Status != "refused" || !strings.Contains(long.Reason, "longer than") ||
			long.Publisher == "" || long.Digest == "" || long.UploadedBy != "admin" {
			t.Errorf("the over-long publisher reads %+v", long)
		}
		if bounded.Status != "refused" || !strings.Contains(bounded.Reason, "larger than") ||
			bounded.Publisher != "" || bounded.UploadedBy != "admin" {
			t.Errorf("the request past the bound reads %+v", bounded)
		}

		// The same, for a supplier advisory: past the bound, and naming
		// itself with more than a name records.
		if got := r.Advised(t, "admin", "dsa-big.json", said+strings.Repeat(" ", 2<<20)); got.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("an advisory past the bound answered %d: %s", got.Code, got.Body.String())
		}
		named := strings.Repeat("D", 200)
		httpapitest.RefusedWith(t, r.Advised(t, "admin", "dsa-long.json",
			httpapitest.SupplierAdvisory(named, "known_not_affected", "3.7.0")), http.StatusUnprocessableEntity)
		httpapitest.RefusedWith(t, r.Advised(t, "admin", "dsa-broken.json", "{"), http.StatusUnprocessableEntity)
		var advisories documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/supplier-advisories", &advisories)
		if advisories.Total != 3 || len(advisories.Items) != 3 {
			t.Fatalf("the advisory list holds %+v; want the three refusals", advisories.Items)
		}
		if broken := advisories.Items[0]; broken.Status != "refused" || broken.Document != "dsa-broken.json" ||
			broken.Reason == "" || broken.Identifier != "" {
			t.Errorf("the advisory nothing can read reads %+v", broken)
		}
		if named := advisories.Items[1]; named.Status != "refused" || !strings.Contains(named.Reason, "longer than") ||
			named.Identifier == "" || named.Document != "dsa-long.json" || named.UploadedBy != "admin" {
			t.Errorf("the advisory naming itself at length reads %+v", named)
		}
		if big := advisories.Items[2]; big.Status != "refused" || !strings.Contains(big.Reason, "larger than") ||
			big.UploadedBy != "admin" {
			t.Errorf("the advisory past the bound reads %+v", big)
		}

		var kinds struct {
			Items []struct {
				Type   string `json:"type"`
				Latest *struct {
					Status string `json:"status"`
					Reason string `json:"reason"`
				} `json:"latest"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/uploads", &kinds)
		for _, each := range kinds.Items {
			if each.Type == "vex" && (each.Latest == nil || each.Latest.Status != "refused" ||
				each.Latest.Reason != long.Reason) {
				t.Errorf("the VEX documents' newest reads %+v; want the refusal", each.Latest)
			}
		}
	})
}

func TestAnUploadShedAtTheSimultaneousLimitIsNotRecordedAsRefused(t *testing.T) {
	// Answered 503: the deployment was busy, and nothing is wrong with the
	// document.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if _, _, err := setting.NewStore(r.DB.DB).Change(t.Context(), setting.UploadsAtOnce, "1"); err != nil {
			t.Fatal(err)
		}
		said := httpapitest.Said("fixed", "", "")
		whole, kind := httpapitest.Form(t, httpapitest.Part{Field: "statements", Filename: "debian.json", Content: said})
		content := whole.Bytes()

		// The first upload is held part way through its body, so it holds
		// its place while the second arrives.
		pr, pw := io.Pipe()
		done := make(chan int)
		go func() {
			done <- r.Post(t, "admin", http.MethodPost, "/v1/products/mine/vex-documents?publisher=debian",
				pr, kind).Code
		}()
		if _, err := pw.Write(content[:64]); err != nil {
			t.Fatal(err)
		}
		httpapitest.RefusedWith(t, r.Vexed(t, "admin", "ubuntu", said), http.StatusServiceUnavailable)
		if _, err := pw.Write(content[64:]); err != nil {
			t.Fatal(err)
		}
		_ = pw.Close()
		if code := <-done; code != http.StatusCreated {
			t.Fatalf("the upload holding the place answered %d", code)
		}

		var vex documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/vex-documents", &vex)
		if vex.Total != 1 || len(vex.Items) != 1 || vex.Items[0].Status != "completed" {
			t.Errorf("the VEX list holds %+v; want the upload taken alone", vex.Items)
		}
	})
}
