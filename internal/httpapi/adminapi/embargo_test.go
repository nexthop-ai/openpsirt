// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTheEmbargoAScreenStatesIsTheOneTheSettingHolds(t *testing.T) {
	// Report-a-flaw states the date an undisclosed flaw from outside will be
	// given. A screen stating the shipped default contradicts a deployment
	// that set another.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		var who struct {
			DiscloseAfter string `json:"disclose_after"`
		}
		httpapitest.Read(t, r, "triager", "/v1/session/me", &who)
		if who.DiscloseAfter != "2160h0m0s" {
			t.Fatalf("the shipped embargo is published as %q, want 2160h0m0s", who.DiscloseAfter)
		}

		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/disclosure.after",
			`{"value":"1080h"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the embargo answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.Read(t, r, "triager", "/v1/session/me", &who)
		if who.DiscloseAfter != "1080h0m0s" {
			t.Fatalf("a set embargo is published as %q, want 1080h0m0s", who.DiscloseAfter)
		}
	})
}
