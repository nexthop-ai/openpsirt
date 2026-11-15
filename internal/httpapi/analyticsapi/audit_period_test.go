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
		before := time.Now().UTC()
		file := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/audit.json?from=2026-01-01", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		if !httpapitest.StatesAMomentSince(file.Body.String(), "to", before) {
			t.Errorf("a file open at the end does not state the moment it ends: %s",
				file.Body.String()[:min(300, len(file.Body.String()))])
		}
		unasked := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet, "/v1/audit.json", "")
		if !httpapitest.StatesAMomentSince(unasked.Body.String(), "to", before) {
			t.Errorf("a file asked for no period does not state the moment it ends: %s",
				unasked.Body.String()[:min(300, len(unasked.Body.String()))])
		}
		named := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/audit.json?from=2026-01-01&to=2099-01-01", "")
		if !strings.Contains(named.Body.String(), `"to":"2099-01-01"`) {
			t.Errorf("a file given an end does not state that day: %s",
				named.Body.String()[:min(300, len(named.Body.String()))])
		}
	})
}

// TestTheAuditLogAnswersTheDecisionsProposedInThePeriodAsked pins the period
// to the proposal's date: from is the first day held and to the first day
// after it, so a period ending on the day a decision was proposed leaves it out.
func TestTheAuditLogAnswersTheDecisionsProposedInThePeriodAsked(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)
		r.Aged(t, decision, "proposed_at", time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC))
		for _, c := range []struct {
			period string
			want   int
		}{
			{"from=2026-03-01&to=2026-04-01", 1},
			{"from=2026-03-10&to=2026-03-11", 1},
			{"from=2026-04-01&to=2026-05-01", 0},
			{"from=2026-02-01&to=2026-03-10", 0},
			{"from=2026-03-11", 0},
		} {
			for _, path := range []string{"/v1/audit", "/v1/audit/decisions"} {
				var got struct {
					Total int `json:"total"`
				}
				httpapitest.Read(t, r, "private-triage", path+"?"+c.period, &got)
				if got.Total != c.want {
					t.Errorf("%s?%s holds %d decisions, want %d", path, c.period, got.Total, c.want)
				}
			}
		}
	})
}
