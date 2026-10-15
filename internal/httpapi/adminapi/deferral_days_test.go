// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// A deferral threshold is a whole number of days, because a deferral is dated
// in days and the decision form is told the threshold in days.
func TestADeferralThresholdIsAWholeNumberOfDays(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		const at = "/v1/settings/" + setting.DeferralThreshold
		for _, value := range []string{"12h", "36h"} {
			got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, at, `{"value":"`+value+`"}`)
			if got.Code != http.StatusUnprocessableEntity {
				t.Errorf("a threshold of %s answered %d, want 422: %s", value, got.Code, got.Body.String())
			}
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, at,
			`{"value":"48h"}`); got.Code >= 300 {
			t.Fatalf("a threshold of two days answered %d: %s", got.Code, got.Body.String())
		}
		var me struct {
			DeferralDays int `json:"deferral_days"`
		}
		httpapitest.Read(t, r, "triager", "/v1/session/me", &me)
		if me.DeferralDays != 2 {
			t.Errorf("a threshold of two days publishes %d", me.DeferralDays)
		}
	})
}

// The limits a screen is told are the shipped ones where nobody has set them,
// and the set ones where somebody has.
func TestTheSessionPublishesTheLimitsInForce(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		type limits struct {
			DeferralDays int `json:"deferral_days"`
			BulkCap      int `json:"bulk_cap"`
		}
		var me limits
		httpapitest.Read(t, r, "triager", "/v1/session/me", &me)
		shipped := limits{
			DeferralDays: int(triage.DefaultDeferralThreshold.Hours() / 24),
			BulkCap:      triage.DefaultTogetherCap,
		}
		if me != shipped {
			t.Errorf("with nothing set the session publishes %+v, want %+v", me, shipped)
		}

		for name, value := range map[string]string{
			setting.DeferralThreshold: "240h",
			setting.TogetherCap:       "7",
		} {
			if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/"+name,
				`{"value":"`+value+`"}`); got.Code >= 300 {
				t.Fatalf("setting %s answered %d: %s", name, got.Code, got.Body.String())
			}
		}
		me = limits{}
		httpapitest.Read(t, r, "triager", "/v1/session/me", &me)
		if want := (limits{DeferralDays: 10, BulkCap: 7}); me != want {
			t.Errorf("with both set the session publishes %+v, want %+v", me, want)
		}
	})
}

// A threshold stored under a day still publishes a day, because omitted it
// reads to the decision form as no threshold while the server enforces one.
func TestAThresholdUnderADayStillPublishesOne(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if _, _, err := setting.NewStore(r.DB.DB).Change(t.Context(), setting.DeferralThreshold,
			"12h"); err != nil {
			t.Fatal(err)
		}
		var me struct {
			DeferralDays *int `json:"deferral_days"`
		}
		httpapitest.Read(t, r, "triager", "/v1/session/me", &me)
		if me.DeferralDays == nil || *me.DeferralDays != 1 {
			t.Errorf("a threshold of twelve hours publishes %v, want 1", me.DeferralDays)
		}
	})
}

// How long a build may go unscanned is a whole number of days, because the
// scanning screen states it in days and flags a build against that number.
// One stored between two days is read as the later whole day.
func TestQuietAfterIsAWholeNumberOfDays(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		const at = "/v1/settings/" + setting.QuietAfter
		for _, value := range []string{"12h", "36h"} {
			got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, at, `{"value":"`+value+`"}`)
			if got.Code != http.StatusUnprocessableEntity {
				t.Errorf("quiet after %s answered %d, want 422: %s", value, got.Code, got.Body.String())
			}
		}
		if _, _, err := setting.NewStore(r.DB.DB).Change(t.Context(), setting.QuietAfter, "12h"); err != nil {
			t.Fatal(err)
		}
		var scanning struct {
			QuietAfterDays int `json:"quiet_after_days"`
		}
		httpapitest.Read(t, r, "admin", "/v1/scanning", &scanning)
		if scanning.QuietAfterDays != 1 {
			t.Errorf("quiet after twelve hours publishes %d days, want 1", scanning.QuietAfterDays)
		}
	})
}
