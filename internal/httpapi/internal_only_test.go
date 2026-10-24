// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// Internal material is read under roles of its own. Somebody holding an
// internal role alone reaches the product and reads none of its disclosed or
// undisclosed findings, and somebody holding both of those reads no internal
// finding.
func TestTheInternalRolesReadInternalWorkAlone(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		hidden := r.Embargoed(t)
		// A later scan of the build carries a second issue, made internal.
		// The recorded flaw stays open, because no scan closes one.
		r.ScannedTwoIssues(t)
		const internal = "CVE-2026-1000"
		r.Internal(t, internal)

		lists := []string{"/v1/products/mine/findings", "/v1/findings", "/v1/unassigned"}
		listed := func(t *testing.T, who, path string) map[string]bool {
			t.Helper()
			var out struct {
				Items []struct {
					Vulnerability string `json:"vulnerability"`
				} `json:"items"`
			}
			httpapitest.Read(t, r, who, path, &out)
			seen := map[string]bool{}
			for _, item := range out.Items {
				seen[item.Vulnerability] = true
			}
			return seen
		}
		for _, path := range lists {
			for _, who := range []string{"internal-reader", "internal-triager"} {
				seen := listed(t, who, path)
				if !seen[internal] {
					t.Errorf("%s: %s does not read the internal finding: %v", path, who, seen)
				}
				if seen[hidden] || seen["CVE-2026-9999"] {
					t.Errorf("%s: %s reads a finding it holds no grant for: %v", path, who, seen)
				}
			}
			// Reading both other halves is not reading internal work, and
			// reads both, so the absence above is the grant rather than the
			// list being empty.
			seen := listed(t, "private", path)
			if seen[internal] {
				t.Errorf("%s: a reader of disclosed and undisclosed work reads internal work: %v",
					path, seen)
			}
			if !seen[hidden] || !seen["CVE-2026-9999"] {
				t.Errorf("%s: a reader of both halves does not read both: %v", path, seen)
			}
		}

		// The product is listed to an internal role alone.
		var products struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "internal-reader", "/v1/products", &products)
		if len(products.Items) != 1 || products.Items[0].Name != "mine" {
			t.Errorf("internal reading lists %+v, want the product it is held on", products.Items)
		}

		var who struct {
			Reach []struct {
				MaySee          bool `json:"may_see"`
				ReadsPublic     bool `json:"reads_public"`
				ReadsPrivate    bool `json:"reads_private"`
				ReadsInternal   bool `json:"reads_internal"`
				MayTriage       bool `json:"may_triage"`
				TriagesPublic   bool `json:"triages_public"`
				MayHide         bool `json:"may_hide"`
				TriagesInternal bool `json:"triages_internal"`
				MayAgree        bool `json:"may_agree"`
				AgreesInternal  bool `json:"agrees_internal"`
			} `json:"reach"`
		}
		httpapitest.Read(t, r, "internal-triager", "/v1/session/me", &who)
		if len(who.Reach) != 1 {
			t.Fatalf("the session reaches %d products, want the one granted", len(who.Reach))
		}
		if can := who.Reach[0]; !can.MaySee || can.ReadsPublic || can.ReadsPrivate ||
			!can.ReadsInternal || !can.MayTriage || can.TriagesPublic || can.MayHide ||
			!can.TriagesInternal || !can.MayAgree || !can.AgreesInternal {
			t.Errorf("the session describes internal triage as %+v", can)
		}

		// Somebody who may read internal work is offered for it, and a reader
		// of both other halves is not.
		var offered struct {
			Items []struct {
				Identity string `json:"identity"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "internal-triager",
			"/v1/products/mine/mentionable?visibility=internal", &offered)
		names := map[string]bool{}
		for _, one := range offered.Items {
			names[one.Identity] = true
		}
		if !names["internal-reader"] || names["private"] {
			t.Errorf("internal work offers %v", names)
		}
		if got := httpapitest.AsPerson(t, r, "private", http.MethodGet,
			"/v1/products/mine/mentionable?visibility=internal", ""); got.Code != http.StatusNotFound {
			t.Errorf("asking who reads internal work without reading it answered %d", got.Code)
		}
	})
}
