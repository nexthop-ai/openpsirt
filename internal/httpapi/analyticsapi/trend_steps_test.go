// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestATrendInDaysHasADailyStepEndingToday(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/trend?days=30", "")
		if got.Code != http.StatusOK {
			t.Fatalf("a daily trend answered %d: %s", got.Code, got.Body.String())
		}
		var body struct {
			Items []struct {
				At string `json:"at"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if len(body.Items) != 30 {
			t.Fatalf("%d steps, want 30", len(body.Items))
		}
		today := time.Now().UTC().Format(time.DateOnly)
		yesterday := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
		if last, before := body.Items[29].At, body.Items[28].At; last != today || before != yesterday {
			t.Errorf("the last two steps are dated %s and %s, want %s and %s", before, last, yesterday, today)
		}
		file := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/trend.csv?days=30", "")
		if file.Code != http.StatusOK || !strings.Contains(file.Body.String(), "day,new,corrected,returned") {
			t.Errorf("the daily file answered %d without a day column: %s", file.Code, file.Body.String())
		}
	})
}

func TestATrendAskedInWeeksAndDaysIsRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, route := range trendRoutes {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, route+"?weeks=4&days=30", "")
			if got.Code != http.StatusUnprocessableEntity || !strings.Contains(got.Body.String(), "send one") {
				t.Errorf("%s with weeks and days answered %d, want 422 saying to send one: %s",
					route, got.Code, got.Body.String())
			}
		}
	})
}
