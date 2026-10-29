// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// Security testing material is read under roles of its own. Somebody holding an
// security testing role alone reaches the product and reads none of its disclosed or
// undisclosed findings, and somebody holding both of those reads no security testing
// finding.
func TestTheSecurityTestingRolesReadSecurityTestingWorkAlone(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		hidden := r.Embargoed(t)
		// A later scan of the build carries a second issue, made security testing work.
		// The recorded flaw stays open, because no scan closes one.
		r.ScannedTwoIssues(t)
		const securityTesting = "CVE-2026-1000"
		r.SecurityTesting(t, securityTesting)

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
			for _, who := range []string{"security-testing-reader", "security-testing-triager"} {
				seen := listed(t, who, path)
				if !seen[securityTesting] {
					t.Errorf("%s: %s does not read the security testing finding: %v", path, who, seen)
				}
				if seen[hidden] || seen["CVE-2026-9999"] {
					t.Errorf("%s: %s reads a finding it holds no grant for: %v", path, who, seen)
				}
			}
			// Reading both other halves is not reading security testing work, and
			// reads both, so the absence above is the grant rather than the
			// list being empty.
			seen := listed(t, "private", path)
			if seen[securityTesting] {
				t.Errorf("%s: a reader of disclosed and undisclosed work reads security testing work: %v",
					path, seen)
			}
			if !seen[hidden] || !seen["CVE-2026-9999"] {
				t.Errorf("%s: a reader of both halves does not read both: %v", path, seen)
			}
		}

		// The product is listed to a security testing role alone.
		var products struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products", &products)
		if len(products.Items) != 1 || products.Items[0].Name != "mine" {
			t.Errorf("security testing reading lists %+v, want the product it is held on", products.Items)
		}

		var who struct {
			Reach []struct {
				MaySee                 bool `json:"may_see"`
				ReadsPublic            bool `json:"reads_public"`
				ReadsPrivate           bool `json:"reads_private"`
				ReadsSecurityTesting   bool `json:"reads_security_testing"`
				MayTriage              bool `json:"may_triage"`
				TriagesPublic          bool `json:"triages_public"`
				MayHide                bool `json:"may_hide"`
				TriagesSecurityTesting bool `json:"triages_security_testing"`
				MayAgree               bool `json:"may_agree"`
				AgreesSecurityTesting  bool `json:"agrees_security_testing"`
			} `json:"reach"`
		}
		httpapitest.Read(t, r, "security-testing-triager", "/v1/session/me", &who)
		if len(who.Reach) != 1 {
			t.Fatalf("the session reaches %d products, want the one granted", len(who.Reach))
		}
		if can := who.Reach[0]; !can.MaySee || can.ReadsPublic || can.ReadsPrivate ||
			!can.ReadsSecurityTesting || can.MayTriage || can.TriagesPublic || can.MayHide ||
			!can.TriagesSecurityTesting || can.MayAgree || can.AgreesSecurityTesting {
			t.Errorf("the session describes security testing triage as %+v", can)
		}

		// Somebody who may read security testing work is offered for it, and a reader
		// of both other halves is not.
		var offered struct {
			Items []struct {
				Identity string `json:"identity"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "security-testing-triager",
			"/v1/products/mine/mentionable?visibility=security-testing", &offered)
		names := map[string]bool{}
		for _, one := range offered.Items {
			names[one.Identity] = true
		}
		if !names["security-testing-reader"] || names["private"] {
			t.Errorf("security testing work offers %v", names)
		}
		if got := httpapitest.AsPerson(t, r, "private", http.MethodGet,
			"/v1/products/mine/mentionable?visibility=security-testing", ""); got.Code != http.StatusNotFound {
			t.Errorf("asking who reads security testing work without reading it answered %d", got.Code)
		}
	})
}
