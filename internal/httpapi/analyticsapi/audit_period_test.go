// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

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

// TestAnAuditFileOpenAtTheEndStatesTheMomentItEnds pins what a file asked for
// a start alone says back: the moment it was asked, since the day it falls
// on, said as an end, is by definition outside the period the file covers.
func TestAnAuditFileOpenAtTheEndStatesTheMomentItEnds(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		file := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/audit.json?from=2026-01-01", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		if want := `"to":"` + time.Now().UTC().Format(time.DateOnly) + "T"; !strings.Contains(file.Body.String(), want) {
			t.Errorf("a file open at the end does not state the moment it ends: %s",
				file.Body.String()[:min(300, len(file.Body.String()))])
		}
		named := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/audit.json?from=2026-01-01&to=2099-01-01", "")
		if !strings.Contains(named.Body.String(), `"to":"2099-01-01"`) {
			t.Errorf("a file given an end does not state that day: %s",
				named.Body.String()[:min(300, len(named.Body.String()))])
		}
	})
}
