// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// The hub's counts of code findings are at security testing visibility: a
// reader of the product holding none is refused the figures, never answered
// zeros, and the queue and the chooser it reaches narrow in the data layer.
func TestWhoMayCountCodeFindingsAtAComponent(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		const (
			counts       = "/v1/products/mine/components/mine-src/code-finding-counts"
			theirCounts  = "/v1/products/theirs/components/mine-src/code-finding-counts"
			trend        = hubBuild + "/components/libmine1/code-finding-trend"
			absentTrend  = hubBuild + "/components/nosuch/code-finding-trend"
			tree         = hubBuild + "/components?code_findings=true"
			plainTree    = hubBuild + "/components"
			around       = hubBuild + "/components/libmine1/around?code_findings=true"
			absentAround = hubBuild + "/components/nosuch/around?code_findings=true"
			queue        = hubQueue + "?component=mine-src"
			beneath      = hubQueue + "?beneath=libmine1&branch_or_tag=master&variant=broadcom"
			chooser      = "/v1/components?q=mine"
		)
		for _, c := range []struct {
			who  string
			path string
			want int
		}{
			{"", counts, http.StatusUnauthorized},
			{"security-testing-reader", counts, http.StatusOK},
			{"security-testing-triager", counts, http.StatusOK},
			{"code-finding-handler", counts, http.StatusOK},
			{"reader", counts, http.StatusForbidden},
			{"private-triage", counts, http.StatusForbidden},
			{"approver", counts, http.StatusNotFound},
			{"outsider", counts, http.StatusNotFound},
			{"security-testing-reader", theirCounts, http.StatusNotFound},

			{"", trend, http.StatusUnauthorized},
			{"security-testing-reader", trend, http.StatusOK},
			{"reader", trend, http.StatusForbidden},
			{"private", trend, http.StatusForbidden},
			{"approver", trend, http.StatusNotFound},
			{"outsider", trend, http.StatusNotFound},
			// Authorized before the name is resolved: a name held and a name
			// not held are refused alike.
			{"reader", absentTrend, http.StatusForbidden},

			{"", tree, http.StatusUnauthorized},
			{"security-testing-reader", tree, http.StatusOK},
			{"reader", tree, http.StatusForbidden},
			{"reader", plainTree, http.StatusOK},
			{"private", around, http.StatusForbidden},
			// Authorized before the name is resolved, as the trend is.
			{"private", absentAround, http.StatusForbidden},
			{"security-testing-triager", around, http.StatusOK},
			{"approver", tree, http.StatusNotFound},

			{"", queue, http.StatusUnauthorized},
			{"security-testing-reader", queue, http.StatusOK},
			{"reader", queue, http.StatusOK},
			{"approver", queue, http.StatusNotFound},
			{"outsider", beneath, http.StatusNotFound},
			{"security-testing-reader", beneath, http.StatusOK},

			{"", chooser, http.StatusUnauthorized},
			{"reader", chooser, http.StatusOK},
			{"security-testing-reader", chooser, http.StatusOK},
			{"approver", chooser, http.StatusOK},
		} {
			if got := httpapitest.AsPerson(t, r, c.who, http.MethodGet, c.path, ""); got.Code != c.want {
				t.Errorf("%q GET %s = %d, want %d: %s", c.who, c.path, got.Code, c.want, got.Body.String())
			}
		}

		// What each reaches is counted only as far as they read.
		for _, c := range []struct {
			who   string
			path  string
			total int
		}{
			{"reader", queue, 0},
			{"security-testing-reader", queue, 1},
			{"reader", beneath, 0},
			{"security-testing-triager", beneath, 2},
		} {
			got := hubQueueOf(t, r, c.who, c.path[len(hubQueue):])
			if got.Total != c.total || got.States["open"] != c.total {
				t.Errorf("%s reads %d listed and %d open at %s; want %d", c.who, got.Total, got.States["open"], c.path, c.total)
			}
		}
		for _, c := range []struct {
			who          string
			issues, code bool
		}{
			{"reader", true, false},
			{"security-testing-reader", false, true},
			{"code-finding-handler", true, true},
		} {
			w := httpapitest.AsPerson(t, r, c.who, http.MethodGet, chooser, "")
			var got struct {
				Items []map[string]json.RawMessage `json:"items"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Items) != 1 {
				t.Fatalf("%s's chooser is %s: %v", c.who, w.Body.String(), err)
			}
			_, issues := got.Items[0]["issues"]
			_, code := got.Items[0]["code_findings"]
			if issues != c.issues || code != c.code {
				t.Errorf("%s's chooser carries issues %v and code findings %v; want %v and %v",
					c.who, issues, code, c.issues, c.code)
			}
		}
		var approver struct {
			Items []hubMatch `json:"items"`
		}
		httpapitest.Read(t, r, "approver", chooser, &approver)
		if len(approver.Items) != 0 {
			t.Errorf("somebody reading no product finds %+v", approver.Items)
		}
	})
}
