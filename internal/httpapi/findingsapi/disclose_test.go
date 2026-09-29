// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestDisclosingAnIssueMakesItReadableToEverybody(t *testing.T) {
	// Before the date it waits for a second person. Agreed, the finding is
	// readable to somebody who reads only disclosed work, whoever holds it is
	// told, and it cannot be disclosed twice.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"Not announced anywhere.",`+
				`"severity":"high","component":"libnl-3-200"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
			Component  string `json:"component"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		finding := "/v1/products/mine/streams/master/variants/broadcom/findings/" +
			recorded.Identifier + "/components/" + recorded.Component
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, finding+"/assignment",
			`{"person":"private"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, finding, ""), http.StatusNotFound)

		at := "/v1/products/mine/issues/" + recorded.Identifier + "/disclosure"
		// A reason missing, or one the text policy refuses, is the caller's to
		// fix, and says so.
		for _, reason := range []string{`""`, `"   "`, `"<b>leaked</b>"`} {
			if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at,
				`{"reason":`+reason+`}`); got.Code != http.StatusUnprocessableEntity {
				t.Errorf("disclosing for the reason %s answered %d, want 422: %s",
					reason, got.Code, got.Body.String())
			}
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, at, ""), http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "triager", http.MethodPost, at, `{"reason":"Because."}`), http.StatusNotFound)

		got = httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at, `{"reason":"The advisory is out."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("disclosing answered %d: %s", got.Code, got.Body.String())
		}
		var asked struct {
			ID            int64  `json:"id"`
			Act           string `json:"act"`
			NeedsApproval bool   `json:"needs_approval"`
			InForce       bool   `json:"in_force"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &asked); err != nil {
			t.Fatal(err)
		}
		if asked.Act != "disclosure" || !asked.NeedsApproval || asked.InForce {
			t.Fatalf("disclosing months before the date recorded %+v, want a disclosure waiting", asked)
		}
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at,
			`{"reason":"Again."}`); got.Code != http.StatusConflict {
			t.Errorf("asking twice answered %d, want 409", got.Code)
		}

		approval := fmt.Sprintf("/v1/disclosure-movements/%d/approval", asked.ID)
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, approval, `{}`); got.Code != http.StatusNoContent {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodGet, finding, ""); got.Code != http.StatusOK {
			t.Errorf("a disclosed finding answered %d to a public reader: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodGet, at, ""); got.Code != http.StatusOK ||
			!strings.Contains(got.Body.String(), "The advisory is out.") {
			t.Errorf("a public reader reading the disclosed embargo's history got %d: %s",
				got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at,
			`{"reason":"Once more."}`); got.Code != http.StatusConflict {
			t.Errorf("disclosing a disclosed issue answered %d, want 409", got.Code)
		}

		var told struct {
			Items []struct {
				Kind string `json:"kind"`
				Body string `json:"body"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "private", "/v1/notifications", &told)
		heard := false
		for _, item := range told.Items {
			if item.Kind == "disclosed" && strings.Contains(item.Body, recorded.Identifier) {
				heard = true
			}
		}
		if !heard {
			t.Errorf("the person holding it was not told it was disclosed: %+v", told.Items)
		}
	})
}

// The person whose act makes an issue public is not told it is public, even
// where they hold a place of it. Verified by deleting the skip in
// toldDisclosed: the agreer is told of their own act.
func TestWhoeverDisclosesAnIssueIsNotToldOfIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"Not announced anywhere.",`+
				`"severity":"high","component":"libnl-3-200"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
			Component  string `json:"component"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		finding := "/v1/products/mine/streams/master/variants/broadcom/findings/" +
			recorded.Identifier + "/components/" + recorded.Component
		// The person who will agree to the disclosure holds the finding.
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, finding+"/assignment",
			`{"person":"private-dispatcher"}`); got.Code != http.StatusNoContent {
			t.Fatalf("taking the finding answered %d: %s", got.Code, got.Body.String())
		}
		at := "/v1/products/mine/issues/" + recorded.Identifier + "/disclosure"
		got = httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at, `{"reason":"The advisory is out."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("disclosing answered %d: %s", got.Code, got.Body.String())
		}
		var asked struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &asked); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
			fmt.Sprintf("/v1/disclosure-movements/%d/approval", asked.ID), `{}`); got.Code != http.StatusNoContent {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}

		var told struct {
			Items []struct {
				Kind string `json:"kind"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "private-dispatcher", "/v1/notifications", &told)
		for _, item := range told.Items {
			if item.Kind == "disclosed" {
				t.Errorf("the person who disclosed the issue was told of it: %+v", told.Items)
			}
		}
	})
}
