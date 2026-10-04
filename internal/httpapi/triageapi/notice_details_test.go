// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// staged is the obligation list as one person reads it, with what a window
// counts from and what a notice carried.
type staged struct {
	Items []struct {
		Windows []struct {
			Window struct {
				Name     string `json:"name"`
				FromName string `json:"from_name"`
			} `json:"window"`
			Started  bool   `json:"started"`
			StartsAt string `json:"starts_at"`
			EndsAt   string `json:"ends_at"`
		} `json:"windows"`
		Told []struct {
			Reference string   `json:"reference"`
			Places    []string `json:"places"`
			Malicious string   `json:"suspected_malicious"`
		} `json:"told"`
	} `json:"items"`
}

// A window counting from another window's notice is on the shelf with no start
// and no end, and raises nothing, until that notice is recorded. Then it runs
// from the notice, and says so.
func TestAWindowCountingFromANoticeRaisesNothingUntilTheNotice(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		notification := r.Declared(t, "Notification", 72)
		got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/obligation-windows",
			fmt.Sprintf(`{"name":"Final report","hours":720,"from":%d}`, notification))
		if got.Code != http.StatusCreated {
			t.Fatalf("declaring a window counting from a notice answered %d: %s", got.Code, got.Body.String())
		}
		record := r.AttackedAt(t, time.Now().UTC().Add(-2*time.Hour))

		var seen staged
		httpapitest.Read(t, r, "private-triage", "/v1/obligations", &seen)
		final := seen.Items[0].Windows[1]
		if final.Window.Name != "Final report" || final.Window.FromName != "Notification" {
			t.Fatalf("the second window reads %+v", final)
		}
		if final.Started || final.StartsAt != "" || final.EndsAt != "" {
			t.Errorf("before any notice the window reads %+v, want no start and no end", final)
		}
		if open := r.Alerts(t, "private-triage", "obligation-open"); len(open) != 1 ||
			!httpapitest.Contains(open[0], "Notification") {
			t.Errorf("before any notice the running windows are %v, want the notification alone", open)
		}

		told := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/exploited-here/%d/told", record),
			fmt.Sprintf(`{"recipient":"A regulator","told_at":%q,"said":"Notified.","window":%d}`,
				told.Format(time.RFC3339), notification),
		); got.Code != http.StatusCreated {
			t.Fatalf("recording a notice answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.Read(t, r, "private-triage", "/v1/obligations", &seen)
		final = seen.Items[0].Windows[1]
		if !final.Started || final.StartsAt != told.Format(time.RFC3339) {
			t.Errorf("after the notice the window reads %+v, want it started at %s", final, told)
		}
		open := r.Alerts(t, "private-triage", "obligation-open")
		if len(open) != 1 || !httpapitest.Contains(open[0], `the first notice for "Notification"`) {
			t.Errorf("after the notice the running windows are %v, want the final report", open)
		}
	})
}

// A notice carries the recipient's reference, the places it named and what it
// said about malice, in the response that records it and on the shelf. A word
// about malice outside the three is refused before anything is stored.
func TestANoticeCarriesItsReferencePlacesAndWordOnMalice(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		record := r.AttackedAt(t, time.Now().UTC().Add(-2*time.Hour))
		path := fmt.Sprintf("/v1/exploited-here/%d/told", record)
		at := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)

		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, path,
			fmt.Sprintf(`{"recipient":"A regulator","told_at":%q,"said":"Told.",`+
				`"suspected_malicious":"perhaps"}`, at)); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a word about malice nobody offered answered %d", got.Code)
		}
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, path,
			fmt.Sprintf(`{"recipient":"A regulator","told_at":%q,"said":"Told.",`+
				`"reference":"CASE-42","places":["Ireland","Germany"],"suspected_malicious":"yes"}`, at))
		if got.Code != http.StatusCreated {
			t.Fatalf("recording a notice answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Reference string   `json:"reference"`
			Places    []string `json:"places"`
			Malicious string   `json:"suspected_malicious"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		if recorded.Reference != "CASE-42" || recorded.Malicious != "yes" ||
			!slices.Equal(recorded.Places, []string{"Ireland", "Germany"}) {
			t.Errorf("the notice recorded reads %+v", recorded)
		}

		var seen staged
		httpapitest.Read(t, r, "private-triage", "/v1/obligations", &seen)
		if len(seen.Items[0].Told) != 1 {
			t.Fatalf("%d notices on the shelf, want 1", len(seen.Items[0].Told))
		}
		if on := seen.Items[0].Told[0]; on.Reference != "CASE-42" || on.Malicious != "yes" ||
			!slices.Equal(on.Places, []string{"Ireland", "Germany"}) {
			t.Errorf("the notice on the shelf reads %+v", on)
		}
	})
}
