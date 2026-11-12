// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// rewritesWaiting is how many deadline rewrites are queued and not yet claimed.
func rewritesWaiting(t *testing.T, r *httpapitest.Reach) int {
	t.Helper()
	n, err := r.DB.DB.NewSelect().Table("job").
		Where(`"kind" = ?`, queue.Deadlines).Where(`"state" = ?`, queue.Pending).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

// A policy stated again is no change: it leaves no trail row saying it moved
// from a value to the same value, and queues no rewrite of deadlines it did
// not move. Stated differently, it is recorded.
func TestAPolicyStatedAgainIsNoChange(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		done(t, r, http.MethodPost, "/v1/products/mine/branches-and-tags", `{"name":"v9","kind":"tag"}`)
		for _, each := range []struct{ what, path, first, second string }{
			{"a setting", "/v1/settings/remediation.due.high", `{"value":"720h"}`, `{"value":"480h"}`},
			{"pair thresholds", "/v1/products/mine/pair-thresholds",
				`{"share":80,"approvers":3}`, `{"share":70,"approvers":3}`},
			{"publication", "/v1/products/mine/publication", `{"publishes":true}`, `{"publishes":false}`},
			{"a minimum severity", "/v1/products/mine/minimum-severity",
				`{"minimum_severity":"high"}`, `{"minimum_severity":""}`},
			{"a product's end of life", "/v1/products/mine/end-of-life",
				`{"on":"2030-01-31"}`, `{"on":""}`},
			{"a release date", "/v1/products/mine/branches-and-tags/v9/release",
				`{"released_on":"2026-03-31"}`, `{"released_on":"2026-04-01"}`},
			{"a release's end of life", "/v1/products/mine/branches-and-tags/master/end-of-life",
				`{"on":"2030-01-31"}`, `{"on":""}`},
			{"repositories", "/v1/products/mine/repositories",
				`{"hosts":[{"remote":"GitHub.com/","web":"https://github.com/","style":"github"}],"paths":[]}`,
				`{"hosts":[],"paths":[]}`},
		} {
			done(t, r, http.MethodPut, each.path, each.first)
			before, waiting := trailCount(t, r), rewritesWaiting(t, r)
			done(t, r, http.MethodPut, each.path, each.first)
			if rows := trailSince(t, r, before).Items; len(rows) != 0 {
				t.Errorf("%s stated again recorded %+v", each.what, rows)
			}
			if now := rewritesWaiting(t, r); now != waiting {
				t.Errorf("%s stated again queued a rewrite: %d waiting, then %d", each.what, waiting, now)
			}
			done(t, r, http.MethodPut, each.path, each.second)
			if rows := trailSince(t, r, before).Items; len(rows) != 1 {
				t.Errorf("%s changed recorded %d rows, want one: %+v", each.what, len(rows), rows)
			}
		}
	})
}

// A change to what decides a deadline queues one rewrite in the act, and a
// rewrite still waiting takes the changes after it. Run in the process that
// took the request, a restart lost it and every stored deadline kept the old
// policy with nothing saying so.
func TestAPolicyChangeQueuesOneRewriteOfDeadlines(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, each := range []struct{ path, body string }{
			{"/v1/settings/remediation.due.high", `{"value":"720h"}`},
			{"/v1/settings/remediation.due.critical", `{"value":"168h"}`},
			{"/v1/products/mine/minimum-severity", `{"minimum_severity":"high"}`},
			{"/v1/products/mine/end-of-life", `{"on":"2030-01-31"}`},
			{"/v1/products/mine/branches-and-tags/master/end-of-life", `{"on":"2030-01-31"}`},
		} {
			done(t, r, http.MethodPut, each.path, each.body)
			if n := rewritesWaiting(t, r); n != 1 {
				t.Errorf("after %s, %d deadline rewrites are waiting, want one", each.path, n)
			}
		}
	})
}
