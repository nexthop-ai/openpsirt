// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestDisclosingAnIssueMakesItReadableToEverybody(t *testing.T) {
	// Before the date it waits for a second person. Agreed, the finding is
	// readable to somebody who reads only disclosed work, whoever holds it is
	// told, and it cannot be disclosed twice.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		got := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
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
		if got := asPerson(t, r, "private-dispatcher", http.MethodPut, finding+"/assignment",
			`{"person":"private"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "reader", http.MethodGet, finding, ""); got.Code < 400 {
			t.Fatalf("an undisclosed finding was readable to a public reader: %d", got.Code)
		}

		at := "/v1/products/mine/issues/" + recorded.Identifier + "/disclosure"
		// A reason missing, or one the text policy refuses, is the caller's to
		// fix, and says so.
		for _, reason := range []string{`""`, `"   "`, `"<b>leaked</b>"`} {
			if got := asPerson(t, r, "private-triage", http.MethodPost, at,
				`{"reason":`+reason+`}`); got.Code != http.StatusUnprocessableEntity {
				t.Errorf("disclosing for the reason %s answered %d, want 422: %s",
					reason, got.Code, got.Body.String())
			}
		}
		if got := asPerson(t, r, "reader", http.MethodGet, at, ""); got.Code < 400 {
			t.Errorf("a public reader read the history of a running embargo: %d", got.Code)
		}
		if got := asPerson(t, r, "triager", http.MethodPost, at, `{"reason":"Because."}`); got.Code < 400 {
			t.Errorf("somebody holding only public triage disclosed an issue: %d", got.Code)
		}

		got = asPerson(t, r, "private-triage", http.MethodPost, at, `{"reason":"The advisory is out."}`)
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
		if got := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"reason":"Again."}`); got.Code != http.StatusConflict {
			t.Errorf("asking twice answered %d, want 409", got.Code)
		}

		approval := fmt.Sprintf("/v1/disclosure-movements/%d/approval", asked.ID)
		if got := asPerson(t, r, "private-dispatcher", http.MethodPost, approval, `{}`); got.Code != http.StatusNoContent {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "reader", http.MethodGet, finding, ""); got.Code != http.StatusOK {
			t.Errorf("a disclosed finding answered %d to a public reader: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "reader", http.MethodGet, at, ""); got.Code != http.StatusOK ||
			!strings.Contains(got.Body.String(), "The advisory is out.") {
			t.Errorf("a public reader reading the disclosed embargo's history got %d: %s",
				got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "private-triage", http.MethodPost, at,
			`{"reason":"Once more."}`); got.Code != http.StatusConflict {
			t.Errorf("disclosing a disclosed issue answered %d, want 409", got.Code)
		}

		var told struct {
			Items []struct {
				Kind string `json:"kind"`
				Body string `json:"body"`
			} `json:"items"`
		}
		read(t, r, "private", "/v1/notifications", &told)
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
