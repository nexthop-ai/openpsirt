// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// documents is a page of the documents one kind of upload left standing.
type documents struct {
	Items []struct {
		Publisher  string `json:"publisher"`
		Identifier string `json:"identifier"`
		Document   string `json:"document"`
		Digest     string `json:"digest"`
		Fetched    bool   `json:"fetched"`
		Standing   int    `json:"standing"`
		SetAside   int    `json:"set_aside"`
		FirstAt    string `json:"first_received_at"`
		ChangedAt  string `json:"changed_at"`
	} `json:"items"`
	Total int `json:"total"`
}

func TestAnUploadedDocumentIsListedOnceUnderTheKeyItIsReplacedBy(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		// One publisher's statement set, uploaded twice with a different
		// claim: one document whose first claim was set aside.
		for _, said := range []string{
			httpapitest.Said("affected", "", "Upgrade."),
			httpapitest.Said("not_affected", "vulnerable_code_not_present", "Not built."),
		} {
			if got := r.Vexed(t, "admin", "debian", said); got.Code != http.StatusCreated {
				t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
			}
		}
		if got := r.Vexed(t, "admin", "ubuntu", httpapitest.Said("fixed", "", "")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		if got := r.Advised(t, "admin", "dsa-1.json",
			httpapitest.SupplierAdvisory("DSA-1", "known_not_affected", "3.7.0")); got.Code != http.StatusCreated {
			t.Fatalf("uploading an advisory answered %d: %s", got.Code, got.Body.String())
		}

		var vex documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/vex-statements", &vex)
		if vex.Total != 2 || len(vex.Items) != 2 {
			t.Fatalf("the VEX list holds %d of %d; want ubuntu and debian once each: %+v",
				len(vex.Items), vex.Total, vex.Items)
		}
		// The most recently changed first.
		newest, debian := vex.Items[0], vex.Items[1]
		if newest.Publisher != "ubuntu" || debian.Publisher != "debian" {
			t.Errorf("the list reads %q then %q; want the newest first", newest.Publisher, debian.Publisher)
		}
		if debian.Standing != 1 || debian.SetAside != 1 || debian.Document != "debian.json" ||
			debian.Identifier != "" || debian.Digest == "" || debian.Fetched {
			t.Errorf("debian's document reads %+v; want one statement standing and one set aside", debian)
		}
		if debian.FirstAt == "" || debian.ChangedAt < debian.FirstAt {
			t.Errorf("debian's document was first received %q and changed %q", debian.FirstAt, debian.ChangedAt)
		}

		// An advisory is its own kind and never appears among the VEX
		// documents, nor a VEX document among the advisories.
		var advisories documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/supplier-advisories", &advisories)
		if advisories.Total != 1 || len(advisories.Items) != 1 {
			t.Fatalf("the advisory list holds %+v; want DSA-1 alone", advisories.Items)
		}
		if one := advisories.Items[0]; one.Identifier != "DSA-1" || one.Document != "dsa-1.json" ||
			one.Standing != 1 || one.Fetched {
			t.Errorf("the advisory reads %+v", one)
		}

		// A page is a page of documents, and the total is of all of them.
		var first documents
		httpapitest.Read(t, r, "reader", "/v1/products/mine/vex-statements?limit=1&offset=1", &first)
		if first.Total != 2 || len(first.Items) != 1 || first.Items[0].Publisher != "debian" {
			t.Errorf("the second page of one reads %+v of %d; want debian", first.Items, first.Total)
		}

		// Another product holds none of them.
		var theirs documents
		httpapitest.Read(t, r, "admin", "/v1/products/theirs/vex-statements", &theirs)
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
			"/v1/products/mine/vex-statements", "/v1/products/mine/supplier-advisories",
		} {
			for who, want := range map[string]int{
				"reader": http.StatusOK, "internal-reader": http.StatusOK, "admin": http.StatusOK,
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
