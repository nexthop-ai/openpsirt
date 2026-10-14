// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAPersonUploadsOnlyWhereTheyTriage(t *testing.T) {
	// A person may send a build by hand where they triage the product. Somebody
	// who reads it passes every check before that one.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		const at = "/v1/products/mine/streams/master/variants/broadcom/scans"
		send := func(who string) int {
			req := httpapitest.Upload(t, at, httpapitest.Inventory(httpapitest.Nowish(), "libc6"))
			req.Header.Set(httpapitest.TestHeader, who)
			httpapitest.FromOurOwnPage(req)
			rec := httptest.NewRecorder()
			r.Handler.ServeHTTP(rec, req)
			return rec.Code
		}
		scans := func() int {
			n, err := r.DB.DB.NewSelect().Table("scan").Count(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		before := scans()
		if code := send("reader"); code != http.StatusForbidden {
			t.Errorf("a reader of the product sending a build answered %d, want 403", code)
		}
		if after := scans(); after != before {
			t.Errorf("a refused upload left %d scans recorded", after-before)
		}
		if code := send("triager"); code != http.StatusAccepted {
			t.Errorf("a triager of the product sending a build answered %d, want 202", code)
		}
	})
}
