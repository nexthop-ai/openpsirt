// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestANotificationIsAcknowledgedOnlyByWhoeverItWasFor(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut,
			httpapitest.FindingAt("CVE-2026-9999")+"/assignment",
			`{"person":"reader"}`); got.Code != http.StatusNoContent {
			t.Fatalf("handing the finding over answered %d: %s", got.Code, got.Body.String())
		}
		var told struct {
			Items []struct {
				ID int64 `json:"id"`
			} `json:"items"`
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "reader", "/v1/notifications", &told)
		if len(told.Items) == 0 {
			t.Fatal("the person handed the work was told nothing")
		}
		one := "/v1/notifications/" + httpapitest.Itoa(told.Items[0].ID)

		// Somebody else's, answered as one that is not there.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "triager", http.MethodDelete, one, ""),
			http.StatusNotFound)
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodDelete, one, ""); got.Code != http.StatusNoContent {
			t.Fatalf("acknowledging their own answered %d: %s", got.Code, got.Body.String())
		}

		// Everything waiting, at once, and what it counted.
		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut,
			httpapitest.FindingAt("CVE-2026-9999")+"/assignment",
			`{"person":"private"}`); got.Code != http.StatusNoContent {
			t.Fatalf("handing the finding on answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.Read(t, r, "private", "/v1/notifications", &told)
		waiting := told.Total
		got := httpapitest.AsPerson(t, r, "private", http.MethodDelete, "/v1/notifications", "")
		if got.Code != http.StatusOK {
			t.Fatalf("acknowledging everything answered %d: %s", got.Code, got.Body.String())
		}
		var cleared struct {
			Acknowledged int `json:"acknowledged"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &cleared); err != nil {
			t.Fatal(err)
		}
		if waiting == 0 || cleared.Acknowledged != waiting {
			t.Errorf("acknowledging %d waiting answered %d", waiting, cleared.Acknowledged)
		}
		httpapitest.Read(t, r, "private", "/v1/notifications", &told)
		if told.Total != 0 {
			t.Errorf("%d are still waiting after acknowledging everything", told.Total)
		}
	})
}
