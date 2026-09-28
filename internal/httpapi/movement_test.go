// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An extension agreed to after a later one took effect would carry the date
// backwards, so agreeing to it is refused as a conflict. Verified by deleting
// the wrong-direction arm of the agreement handler: it answers 500.
func TestAgreeingToAMovementTheDateHasPassedIsAConflict(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		got := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"Not announced anywhere.","severity":"high"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		extend := "/v1/products/mine/issues/" + recorded.Identifier + "/disclosure/extension"
		asked := func(until string) int64 {
			t.Helper()
			got := asPerson(t, r, "private-triage", http.MethodPost, extend,
				`{"until":"`+until+`","reason":"The fix slipped."}`)
			if got.Code != http.StatusCreated {
				t.Fatalf("asking answered %d: %s", got.Code, got.Body.String())
			}
			var movement struct {
				ID            int64 `json:"id"`
				NeedsApproval bool  `json:"needs_approval"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &movement); err != nil {
				t.Fatal(err)
			}
			if !movement.NeedsApproval {
				t.Fatalf("an extension to %s stood on one person's say-so", until)
			}
			return movement.ID
		}
		nearer := asked("2031-01-01")
		further := asked("2032-01-01")
		agree := func(id int64) *httptest.ResponseRecorder {
			return asPerson(t, r, "private-dispatcher", http.MethodPost,
				fmt.Sprintf("/v1/disclosure-movements/%d/approval", id), `{}`)
		}
		if got := agree(further); got.Code != http.StatusNoContent {
			t.Fatalf("agreeing to the later date answered %d: %s", got.Code, got.Body.String())
		}
		refusedWith(t, agree(nearer), http.StatusConflict)
	})
}
