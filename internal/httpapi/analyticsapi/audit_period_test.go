// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestTheAuditLogRefusesAPeriodHoldingNoDays pins the audit log to the period
// every other report reads: a day named twice, or an end before the start, is
// refused rather than answered as a period in which nothing was decided.
func TestTheAuditLogRefusesAPeriodHoldingNoDays(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		for _, path := range []string{"/v1/audit", "/v1/audit/decisions", "/v1/audit.csv"} {
			for _, period := range []string{"from=2026-05-01&to=2026-05-01", "from=2026-05-02&to=2026-05-01"} {
				httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage",
					http.MethodGet, path+"?"+period, ""), http.StatusUnprocessableEntity)
			}
		}
	})
}
