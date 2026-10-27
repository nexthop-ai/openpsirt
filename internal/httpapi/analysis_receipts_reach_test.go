// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A reader who may not read a build's analyzer runs is answered the same
// whether or not anything was ever sent to the build, so the answer says
// nothing about which builds hold runs.
func TestAnalyzerRunsAreRefusedBeforeTheBuildIsLookedUp(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/products/mine/branches-and-tags",
			`{"name":"fresh","kind":"branch"}`); got.Code >= 300 {
			t.Fatalf("declaring the branch answered %d: %s", got.Code, got.Body)
		}
		const sent = "/v1/products/mine/branches-and-tags/master/variants/broadcom/analyses"
		const unsent = "/v1/products/mine/branches-and-tags/fresh/variants/broadcom/analyses"
		for _, path := range []string{sent, unsent} {
			if got := httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet, path, ""); got.Code != http.StatusOK {
				t.Errorf("an internal reader asking %s was answered %d: %s", path, got.Code, got.Body)
			}
			httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, path, ""), http.StatusNotFound)
		}
	})
}
