// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestStepsEndAtTheComingMidnightUTC(t *testing.T) {
	// Mid-afternoon, so a window ending now and one ending at midnight differ
	// by the hours left in the day, and a fix at 23:00 lands on its own date.
	now := time.Date(2026, 1, 10, 15, 0, 0, 0, time.FixedZone("UTC+5", 5*3600))
	for _, one := range []struct {
		steps core.Steps
		since time.Time
	}{
		{core.Steps{Days: 3}, time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)},
		{core.Steps{Weeks: 2}, time.Date(2025, 12, 28, 0, 0, 0, 0, time.UTC)},
	} {
		since, step, steps, err := one.steps.Window(now)
		if err != nil {
			t.Fatal(err)
		}
		until := since.Add(time.Duration(steps) * step)
		if !since.Equal(one.since) || !until.Equal(time.Date(2026, 1, 11, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("%+v runs from %s to %s, want from %s to the coming midnight UTC, 2026-01-11",
				one.steps, since.UTC(), until.UTC(), one.since)
		}
	}
}

func TestATrendInDaysHasADailyStepEndingToday(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// The server dates its steps by its own clock, so today is whichever
		// day the request ran on, read on both sides of it.
		asked := time.Now().UTC()
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/trend?days=30", "")
		answered := time.Now().UTC()
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
		endingOn := func(day time.Time) bool {
			return body.Items[29].At == day.Format(time.DateOnly) &&
				body.Items[28].At == day.AddDate(0, 0, -1).Format(time.DateOnly)
		}
		if !endingOn(asked) && !endingOn(answered) {
			t.Errorf("the last two steps are dated %s and %s, want the day before the request and its day, %s",
				body.Items[28].At, body.Items[29].At, answered.Format(time.DateOnly))
		}
		file := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/trend.csv?days=30", "")
		if file.Code != http.StatusOK || !strings.Contains(file.Body.String(), "day,new,corrected,returned") {
			t.Errorf("the daily file answered %d without a day column: %s", file.Code, file.Body.String())
		}
	})
}

func TestATrendAskedInWeeksAndDaysIsRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, route := range calendarRoutes {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, route+"?weeks=4&days=30", "")
			if got.Code != http.StatusUnprocessableEntity || !strings.Contains(got.Body.String(), "send one") {
				t.Errorf("%s with weeks and days answered %d, want 422 saying to send one: %s",
					route, got.Code, got.Body.String())
			}
		}
	})
}

// A trend asked in weeks has a point per week, the last of them counting
// what is open now.
func TestATrendInWeeksEndsWithWhatIsOpenNow(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		var trend struct {
			Items []struct {
				At   string `json:"at"`
				Open int    `json:"open"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reader", "/v1/trend?weeks=4", &trend)
		if len(trend.Items) != 4 {
			t.Fatalf("asked for four weeks and got %d points", len(trend.Items))
		}
		if trend.Items[3].Open == 0 {
			t.Error("the trend ends with nothing open, but something is")
		}
	})
}
