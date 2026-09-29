// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// Set-aside work is listed with how much of each kind is still waiting, put
// back once, and refused when it is not set aside.
func TestSetAsideWorkIsListedAndPutBackOnce(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		id := r.SetAside(t, queue.Scan, "target:1")
		if _, err := queue.New(r.DB, queue.DefaultOptions()).Add(t.Context(), queue.Parse, "scan:1"); err != nil {
			t.Fatal(err)
		}

		var listed struct {
			Items []struct {
				ID        int64  `json:"id"`
				Kind      string `json:"kind"`
				Reference string `json:"reference"`
			} `json:"items"`
			Total   int `json:"total"`
			Waiting []struct {
				Kind    string `json:"kind"`
				Waiting int    `json:"waiting"`
				Limit   int    `json:"limit"`
			} `json:"waiting"`
		}
		httpapitest.Read(t, r, "admin", "/v1/work/set-aside", &listed)
		if listed.Total != 1 || len(listed.Items) != 1 || listed.Items[0].ID != id ||
			listed.Items[0].Kind != queue.Scan || listed.Items[0].Reference != "target:1" {
			t.Errorf("the set-aside list reads as %+v", listed)
		}
		if len(listed.Waiting) != len(queue.Kinds()) {
			t.Errorf("waiting names %d kinds, want one per kind: %+v", len(listed.Waiting), listed.Waiting)
		}
		for _, each := range listed.Waiting {
			want := 0
			if each.Kind == queue.Parse {
				want = 1
			}
			if each.Waiting != want || each.Limit <= 0 {
				t.Errorf("%s waiting reads as %+v, want %d waiting under a bound", each.Kind, each, want)
			}
		}

		retry := fmt.Sprintf("/v1/work/set-aside/%d/retry", id)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "triager", http.MethodPost, retry, ""), http.StatusForbidden)
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, retry, ""); got.Code != http.StatusNoContent {
			t.Fatalf("putting the job back answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.Read(t, r, "admin", "/v1/work/set-aside", &listed)
		if listed.Total != 0 {
			t.Errorf("a job put back is still listed as set aside: %+v", listed.Items)
		}
		// Put back already, and never there: neither is set aside.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "admin", http.MethodPost, retry, ""), http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "admin", http.MethodPost,
			"/v1/work/set-aside/999999/retry", ""), http.StatusNotFound)
	})
}

// The data version in force, when it last moved, and whether that is long
// enough ago to count as stopped. Verified by inverting the stale comparison.
func TestTheVulnerabilityDataSaysWhetherItHasStoppedMoving(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		type data struct {
			Version string     `json:"version"`
			MovedAt *time.Time `json:"moved_at"`
			Stale   bool       `json:"stale"`
		}
		var got data
		httpapitest.Read(t, r, "admin", "/v1/vulnerability-data", &got)
		if got.Version != "" || got.MovedAt != nil || got.Stale {
			t.Errorf("a deployment nothing has scanned reads as %+v", got)
		}

		longAgo := time.Now().UTC().AddDate(-1, 0, 0).Truncate(time.Second)
		r.RanAgainst(t, "2025-01-01", longAgo)
		got = data{}
		httpapitest.Read(t, r, "admin", "/v1/vulnerability-data", &got)
		if got.Version != "2025-01-01" || got.MovedAt == nil || !got.Stale {
			t.Errorf("data that last moved a year ago reads as %+v", got)
		}

		r.RanAgainst(t, "2026-01-01", time.Now().UTC().Truncate(time.Second))
		got = data{}
		httpapitest.Read(t, r, "admin", "/v1/vulnerability-data", &got)
		if got.Version != "2026-01-01" || got.Stale {
			t.Errorf("data that moved today reads as %+v", got)
		}

		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/vulnerability-data", ""),
			http.StatusForbidden)
	})
}
