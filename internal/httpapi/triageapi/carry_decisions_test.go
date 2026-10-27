// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// Carrying writes the chosen decision onto the new line as a decision waiting for
// agreement, from the line named in the query to the one in the path, and only
// for somebody who may decide there.
func TestCarryingWritesDecisionsWaitingForASecondPerson(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := r.Scanned(t)
		row, decision := r.DecidedAt(t, occurrence)
		r.Agreed(t, decision)
		r.ScannedTag(t, "v2.0", "3.7.1")

		const at = "/v1/products/mine/branches-and-tags/v2.0/variants/broadcom/carried" +
			"?from=master&from_variant=broadcom"
		var offered struct {
			Moved []struct {
				DecisionOccurrence int64 `json:"decision_occurrence"`
			} `json:"moved"`
		}
		httpapitest.Read(t, r, "triager", at, &offered)
		if len(offered.Moved) != 1 || offered.Moved[0].DecisionOccurrence != row {
			t.Fatalf("the tag was offered %+v, want the one occurrence whose version moved", offered)
		}

		carry := func(who string, ids ...int64) *httptest.ResponseRecorder {
			body, err := json.Marshal(map[string][]int64{"decision_occurrences": ids})
			if err != nil {
				t.Fatal(err)
			}
			return httpapitest.AsPerson(t, r, who, http.MethodPost, at, string(body))
		}
		httpapitest.RefusedWith(t, carry("outsider", row), http.StatusNotFound)
		httpapitest.RefusedWith(t, carry("reader", row), http.StatusNotFound)
		httpapitest.RefusedWith(t, carry("triager", row+1000), http.StatusUnprocessableEntity)

		got := carry("triager", row)
		if got.Code != http.StatusCreated {
			t.Fatalf("carrying answered %d: %s", got.Code, got.Body.String())
		}
		var carried struct {
			Carried int `json:"carried"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &carried); err != nil {
			t.Fatal(err)
		}
		if carried.Carried != 1 {
			t.Errorf("carried %d, want 1", carried.Carried)
		}

		// The decision waits on the tag's version, which is where the path put it.
		var waiting struct {
			Items []struct {
				Finding *struct {
					Stream  string `json:"stream"`
					Version string `json:"version"`
				} `json:"finding"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reviewer", "/v1/review-queue", &waiting)
		if len(waiting.Items) != 1 || waiting.Items[0].Finding == nil ||
			waiting.Items[0].Finding.Stream != "v2.0" || waiting.Items[0].Finding.Version != "3.7.1" {
			t.Errorf("the review queue holds %+v, want one decision waiting on the tag", waiting.Items)
		}
	})
}
