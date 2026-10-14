// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
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

// A threshold stored under a day still publishes a day, because omitted it
// reads to the decision form as no threshold while the server enforces one.
func TestAThresholdUnderADayStillPublishesOne(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if err := setting.NewStore(r.DB.DB).Set(t.Context(), setting.DeferralThreshold,
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
