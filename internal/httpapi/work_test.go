// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// setAside queues one job and sets it aside, answering its identifier.
func (r *reach) setAside(t *testing.T, kind, reference string) int64 {
	t.Helper()
	ctx := t.Context()
	job, err := queue.New(r.db, queue.DefaultOptions()).Add(ctx, kind, reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.NewUpdate().Model((*queue.Job)(nil)).
		Set("state = ?", queue.Dead).Set("attempts = max_attempts").
		Where("id = ?", job.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return job.ID
}

// ranAgainst records a finished scanner run stating a data version.
func (r *reach) ranAgainst(t *testing.T, version string, started time.Time) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.db.DB)
	located, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	finished := started.Add(time.Minute)
	if _, err := r.db.NewInsert().Model(&finding.Run{
		TargetID: target.ID, Scanner: "grype", DatabaseVersion: version, RanHere: true,
		StartedAt: started, FinishedAt: &finished,
	}).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// Set-aside work is listed with how much of each kind is still waiting, put
// back once, and refused when it is not set aside.
func TestSetAsideWorkIsListedAndPutBackOnce(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		id := r.setAside(t, queue.Scan, "target:1")
		if _, err := queue.New(r.db, queue.DefaultOptions()).Add(t.Context(), queue.Parse, "scan:1"); err != nil {
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
		read(t, r, "admin", "/v1/work/set-aside", &listed)
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
		refusedWith(t, asPerson(t, r, "triager", http.MethodPost, retry, ""), http.StatusForbidden)
		if got := asPerson(t, r, "admin", http.MethodPost, retry, ""); got.Code != http.StatusNoContent {
			t.Fatalf("putting the job back answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "admin", "/v1/work/set-aside", &listed)
		if listed.Total != 0 {
			t.Errorf("a job put back is still listed as set aside: %+v", listed.Items)
		}
		// Put back already, and never there: neither is set aside.
		refusedWith(t, asPerson(t, r, "admin", http.MethodPost, retry, ""), http.StatusNotFound)
		refusedWith(t, asPerson(t, r, "admin", http.MethodPost,
			"/v1/work/set-aside/999999/retry", ""), http.StatusNotFound)
	})
}

// The data version in force, when it last moved, and whether that is long
// enough ago to count as stopped. Verified by inverting the stale comparison.
func TestTheVulnerabilityDataSaysWhetherItHasStoppedMoving(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		type data struct {
			Version string     `json:"version"`
			MovedAt *time.Time `json:"moved_at"`
			Stale   bool       `json:"stale"`
		}
		var got data
		read(t, r, "admin", "/v1/vulnerability-data", &got)
		if got.Version != "" || got.MovedAt != nil || got.Stale {
			t.Errorf("a deployment nothing has scanned reads as %+v", got)
		}

		longAgo := time.Now().UTC().AddDate(-1, 0, 0).Truncate(time.Second)
		r.ranAgainst(t, "2025-01-01", longAgo)
		got = data{}
		read(t, r, "admin", "/v1/vulnerability-data", &got)
		if got.Version != "2025-01-01" || got.MovedAt == nil || !got.Stale {
			t.Errorf("data that last moved a year ago reads as %+v", got)
		}

		r.ranAgainst(t, "2026-01-01", time.Now().UTC().Truncate(time.Second))
		got = data{}
		read(t, r, "admin", "/v1/vulnerability-data", &got)
		if got.Version != "2026-01-01" || got.Stale {
			t.Errorf("data that moved today reads as %+v", got)
		}

		refusedWith(t, asPerson(t, r, "triager", http.MethodGet, "/v1/vulnerability-data", ""),
			http.StatusForbidden)
	})
}
