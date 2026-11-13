// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
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
		// again is the first stated in other words where it can be; empty, it
		// is the first word for word.
		for _, each := range []struct{ what, path, first, second, again string }{
			{"a setting", "/v1/settings/remediation.due.high", `{"value":"720h"}`, `{"value":"480h"}`,
				`{"value":"43200m"}`},
			{"pair thresholds", "/v1/products/mine/pair-thresholds",
				`{"share":80,"approvers":3}`, `{"share":70,"approvers":3}`, ""},
			{"publication", "/v1/products/mine/publication", `{"publishes":true}`, `{"publishes":false}`, ""},
			{"a minimum severity", "/v1/products/mine/minimum-severity",
				`{"minimum_severity":"high"}`, `{"minimum_severity":""}`, ""},
			{"a product's end of life", "/v1/products/mine/end-of-life",
				`{"on":"2030-01-31"}`, `{"on":""}`, ""},
			{"a release date", "/v1/products/mine/branches-and-tags/v9/release",
				`{"released_on":"2026-03-31"}`, `{"released_on":"2026-04-01"}`, ""},
			{"a release's end of life", "/v1/products/mine/branches-and-tags/master/end-of-life",
				`{"on":"2030-01-31"}`, `{"on":""}`, ""},
			{"repositories", "/v1/products/mine/repositories",
				// Out of stored order and spelled differently, so only the
				// stored form compares equal.
				`{"hosts":[{"remote":"GitLab.com/","web":"https://gitlab.com/","style":"gitlab"},` +
					`{"remote":"GitHub.com/","web":"https://github.com/","style":"github"}],"paths":[]}`,
				`{"hosts":[],"paths":[]}`, ""},
		} {
			done(t, r, http.MethodPut, each.path, each.first)
			before, waiting := trailCount(t, r), rewritesWaiting(t, r)
			again := each.first
			if each.again != "" {
				again = each.again
			}
			done(t, r, http.MethodPut, each.path, again)
			if each.again != "" {
				var listed struct {
					Items []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"items"`
				}
				httpapitest.Read(t, r, "admin", "/v1/settings", &listed)
				for _, one := range listed.Items {
					if "/v1/settings/"+one.Name == each.path && one.Value != "720h" {
						t.Errorf("%s stated again in other words is stored as %q, want 720h", each.what, one.Value)
					}
				}
			}
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
// rewrite still waiting takes the changes after it.
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

// A policy change whose rewrite of deadlines cannot be queued is refused with
// 503 and records nothing: the change and its rewrite commit together, so the
// stored value and the trail still say what they said.
func TestAPolicyChangeWhoseRewriteCannotBeQueuedRecordsNothing(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		const path = "/v1/settings/remediation.due.high"
		done(t, r, http.MethodPut, path, `{"value":"720h"}`)
		// The rewrite it queued waits to be tried again, so it takes no later
		// change, and with room for one it fills the queue.
		if _, err := r.DB.DB.NewUpdate().Table("job").Set(`"attempts" = 1`).
			Where(`"kind" = ?`, queue.Deadlines).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := setting.NewStore(r.DB.DB).Change(ctx, setting.QueueBacklog, "1"); err != nil {
			t.Fatal(err)
		}
		before := trailCount(t, r)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "admin", http.MethodPut, path,
			`{"value":"480h"}`), http.StatusServiceUnavailable)
		if rows := trailSince(t, r, before).Items; len(rows) != 0 {
			t.Errorf("a change refused for a full queue recorded %+v", rows)
		}
		if held, _, err := setting.NewStore(r.DB.DB).Get(ctx, setting.DueHigh); err != nil || held != "720h" {
			t.Errorf("a change refused for a full queue left the setting %q (%v), want 720h", held, err)
		}
	})
}

// Publication stated off again still withdraws what the product serves: a
// publish run that began before it went off can have written since.
func TestPublicationStatedOffAgainWithdrawsWhatIsStillServed(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		done(t, r, http.MethodPut, "/v1/products/mine/publication", `{"publishes":true}`)
		done(t, r, http.MethodPut, "/v1/products/mine/publication", `{"publishes":false}`)
		var product int64
		if err := r.DB.DB.NewSelect().Table("product").Column("id").
			Where(`"name" = ?`, "mine").Scan(ctx, &product); err != nil {
			t.Fatal(err)
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		sum := sha256.Sum256([]byte("late"))
		late := &publish.Document{
			ProductID: product, Kind: publish.OpenVEX, Subject: "master",
			Path: publish.OpenVEXPath + "mine/master.json", PathDigest: hex.EncodeToString(sum[:]),
			TrackingID: "x", Title: "x", Version: 1, FirstAt: at, CurrentAt: at,
			Statuses: "all", Settled: hex.EncodeToString(sum[:]), Body: "{}",
		}
		if _, err := r.DB.DB.NewInsert().Model(late).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		done(t, r, http.MethodPut, "/v1/products/mine/publication", `{"publishes":false}`)
		held := new(publish.Document)
		if err := r.DB.DB.NewSelect().Model(held).Where(`"pub"."id" = ?`, late.ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if held.WithdrawnAt == nil {
			t.Error("a document written after publication went off is still served once it is stated off again")
		}
	})
}
