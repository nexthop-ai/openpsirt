// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// The anonymous subject reads the security documents a product publishes, and
// no code finding: not one included in its flaw's disclosure whose flaw is disclosed, which is public
// and read by every signed-in reader of the product's disclosed work. Every
// route about code findings answers a request with no credential 401, and the reads
// beneath them answer the subject of the published surface nothing, for a
// product whose documents are published.
func TestTheAnonymousSubjectReadsNoCodeFinding(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, true)
		asked := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/issues/"+flaw+"/disclosure", `{"reason":"fixed in every release"}`)
		if asked.Code != http.StatusCreated {
			t.Fatalf("the disclosure answered %d: %s", asked.Code, asked.Body)
		}
		var movement struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(asked.Body.Bytes(), &movement); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
			fmt.Sprintf("/v1/disclosure-movements/%d/approval", movement.ID), ""); got.Code != http.StatusNoContent {
			t.Fatalf("agreeing to the disclosure answered %d: %s", got.Code, got.Body)
		}
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodGet, at, ""); got.Code != http.StatusOK {
			t.Fatalf("a reader of disclosed work read the disclosed code finding with %d, so this checks nothing: %s",
				got.Code, got.Body)
		}

		reached := 0
		for path, item := range r.API.OpenAPI().Paths {
			if item.Get == nil || !strings.Contains(path, "code-finding") {
				continue
			}
			reached++
			filled := strings.NewReplacer("{product}", "mine", "{branch_or_tag}", "master",
				"{variant}", "broadcom", "{occurrence}", occurrence, "{format}", "csv").Replace(path)
			if got := r.Body(t, "", http.MethodGet, filled); got.Code != http.StatusUnauthorized {
				t.Errorf("%s answered %d with no credential, want 401", filled, got.Code)
			}
		}
		if reached == 0 {
			t.Fatal("no route about code findings was found, so this checked nothing")
		}

		mine, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		anybody := access.Published([]int64{mine.ID})
		if !anybody.Reads(access.Public, mine.ID) {
			t.Fatal("the anonymous subject reads nothing of the product, so this checks nothing")
		}
		build := r.BuildOf(t, httpapitest.SeededBuild)
		if _, err := finding.NewStore(r.DB.DB).CodeFindingAt(ctx, anybody, build, occurrence); !errors.Is(err, finding.ErrNoOpenFinding) {
			t.Errorf("the anonymous subject reading the code finding was answered %v", err)
		}
		for _, state := range []analysis.State{"", analysis.RecordedAsFlaw} {
			queue, err := analysis.CodeFindingsOf(ctx, r.DB.DB, anybody, analysis.Scope{ProductID: mine.ID}, state, 50, 0)
			if err == nil && (queue.Total != 0 || len(queue.Rows) != 0) {
				t.Errorf("the anonymous subject was listed %d code findings in state %q", queue.Total, state)
			}
		}
		if counts, err := analysis.CountsBySeries(ctx, r.DB.DB, anybody, mine.ID); err == nil {
			t.Errorf("the anonymous subject was counted the code findings by series: %+v", counts)
		}
	})
}
