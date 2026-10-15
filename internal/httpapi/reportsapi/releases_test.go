// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// The releases list counts what is open in each build, and a product
// somebody may not read answers exactly as a product nobody declared: one
// that is hidden, and one that is seen and holds nothing they may read.
func TestTheReleasesListAnswersAnUnreadableProductAsUndeclared(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		var releases struct {
			Items []struct {
				Stream  string `json:"stream"`
				Variant string `json:"variant"`
				Open    int    `json:"open"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/releases", &releases)
		found := false
		for _, one := range releases.Items {
			if one.Stream == "master" && one.Variant == "broadcom" {
				found = true
				if one.Open == 0 {
					t.Errorf("the scanned build counts nothing open: %+v", one)
				}
			}
		}
		if !found {
			t.Fatalf("the releases list holds no row for the scanned build: %+v", releases.Items)
		}

		undeclared := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/products/nobody-declared-this/releases", "")
		if undeclared.Code != http.StatusNotFound {
			t.Fatalf("a product nobody declared answered %d: %s", undeclared.Code, undeclared.Body.String())
		}
		// The outsider sees no product. The administrator sees every product
		// and is granted no reading in any.
		for _, who := range []string{"outsider", "admin"} {
			got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/products/mine/releases", "")
			if got.Code != undeclared.Code || got.Body.String() != undeclared.Body.String() {
				t.Errorf("%s reading the releases answered %d %s, want what an undeclared product answers: %s",
					who, got.Code, got.Body.String(), undeclared.Body.String())
			}
		}
	})
}
