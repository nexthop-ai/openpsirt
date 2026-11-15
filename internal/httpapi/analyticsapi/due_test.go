// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestTheRunningOutListNamesWhoHoldsAFinding pins the holder a row of the
// running-out list carries: the identity of whoever a finding is assigned to,
// with their display name beside it, and nothing on a finding nobody holds.
func TestTheRunningOutListNamesWhoHoldsAFinding(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		type row struct {
			Vulnerability string `json:"vulnerability"`
			AssignedTo    string `json:"assigned_to"`
			AssignedName  string `json:"assigned_to_name"`
		}
		var unheld struct {
			Items []row `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/running-out?days=365", &unheld)
		if len(unheld.Items) == 0 {
			t.Fatal("nothing is running out, so this checked nothing")
		}
		for _, one := range unheld.Items {
			if one.AssignedTo != "" || one.AssignedName != "" {
				t.Errorf("a finding nobody holds names a holder: %+v", one)
			}
		}

		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut,
			httpapitest.FindingAt("CVE-2026-9999")+"/assignment",
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		var held struct {
			Items []row `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/running-out?days=365", &held)
		found := false
		for _, one := range held.Items {
			if one.Vulnerability != "CVE-2026-9999" {
				continue
			}
			found = true
			if one.AssignedTo != "triager" || one.AssignedName != httpapitest.ShownAs("triager") {
				t.Errorf("the assigned finding names its holder as %q (%q), want triager (%q)",
					one.AssignedTo, one.AssignedName, httpapitest.ShownAs("triager"))
			}
		}
		if !found {
			t.Fatalf("the assigned finding is not running out: %+v", held.Items)
		}
	})
}
