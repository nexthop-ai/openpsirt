// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTheEffortReportNamesATeamNobodyUsesAsEveryRouteDoes(t *testing.T) {
	// A team is not product data, and the caller wrote its name: every route
	// that resolves one answers in the same words, naming it.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		got := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/effort?team=nobody-at-all", "")
		if got.Code != http.StatusNotFound {
			t.Fatalf("a team nobody uses answered %d: %s", got.Code, got.Body.String())
		}
		if !strings.Contains(got.Body.String(), `"no team is known as nobody-at-all"`) {
			t.Errorf("a team nobody uses was answered %s", got.Body.String())
		}
	})
}
