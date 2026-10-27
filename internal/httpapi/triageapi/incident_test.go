// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A finding shows every incident in its product through its issue, each with
// the notices recorded against that incident and no other, and a cleared one
// with who cleared it and why. Verified by handing every incident the notices
// of the first: the standing incident then carries one.
func TestAFindingShowsItsIncidentsWithWhoWasTold(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		early := r.Declared(t, "Early warning", 24)
		known := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
		first := r.AttackedAt(t, known)
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/incidents/%d/told", first),
			fmt.Sprintf(`{"recipient":"ENISA","told_at":%q,"said":"An attack.","window":%d}`,
				time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), early),
		); got.Code != http.StatusCreated {
			t.Fatalf("recording a notice answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodDelete,
			fmt.Sprintf("/v1/incidents/%d", first),
			`{"because":"The captures were of a different deployment."}`,
		); got.Code != http.StatusNoContent {
			t.Fatalf("clearing answered %d: %s", got.Code, got.Body.String())
		}
		second := r.AttackedAt(t, known.Add(time.Hour))

		var shown struct {
			Incident []struct {
				ID             int64  `json:"id"`
				KnownAt        string `json:"known_at"`
				Grounds        string `json:"grounds"`
				RecordedBy     string `json:"recorded_by"`
				ClearedBy      string `json:"cleared_by"`
				ClearedBecause string `json:"cleared_because"`
				Standing       bool   `json:"standing"`
				Told           []struct {
					Recipient string `json:"recipient"`
					WindowID  int64  `json:"window_id"`
					Window    string `json:"window"`
				} `json:"told"`
			} `json:"incidents"`
		}
		httpapitest.Read(t, r, "private-triage", httpapitest.FindingAt("CVE-2026-9999"), &shown)
		if len(shown.Incident) != 2 {
			t.Fatalf("the finding shows %d records, want 2: %+v",
				len(shown.Incident), shown.Incident)
		}
		byID := map[int64]int{}
		for i, each := range shown.Incident {
			byID[each.ID] = i
		}
		standing := shown.Incident[byID[second]]
		if !standing.Standing || standing.RecordedBy != "private-triage" ||
			standing.Grounds != "A customer sent packet captures." || standing.KnownAt == "" ||
			standing.ClearedBy != "" || len(standing.Told) != 0 {
			t.Errorf("the standing record reads as %+v", standing)
		}
		cleared := shown.Incident[byID[first]]
		if cleared.Standing || cleared.ClearedBy != "private-triage" ||
			cleared.ClearedBecause != "The captures were of a different deployment." {
			t.Errorf("the cleared record reads as %+v", cleared)
		}
		if len(cleared.Told) != 1 || cleared.Told[0].Recipient != "ENISA" ||
			cleared.Told[0].WindowID != early || cleared.Told[0].Window != "Early warning" {
			t.Errorf("the notice on the cleared record reads as %+v", cleared.Told)
		}
	})
}
