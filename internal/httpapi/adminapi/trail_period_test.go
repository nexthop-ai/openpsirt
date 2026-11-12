// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestTheTrailFileEndsWhenItWasAskedFor pins an open period's end to the moment
// the file was asked for, stated in the file as that moment, so a change
// recorded while it is written lies outside the period on every page. A
// rolling window's start is a moment too, and is stated as one.
func TestTheTrailFileEndsWhenItWasAskedFor(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		before := time.Now().UTC()
		file := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/administration/changes.json", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		if !httpapitest.StatesAMomentSince(file.Body.String(), "to", before) {
			t.Errorf("a file asked for no period does not state the moment it ends: %s",
				file.Body.String()[:min(300, len(file.Body.String()))])
		}
		week := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/administration/changes.json?days=7", "")
		if week.Code != http.StatusOK {
			t.Fatalf("exporting a week answered %d: %s", week.Code, week.Body.String())
		}
		if !httpapitest.StatesAMomentSince(week.Body.String(), "from", before.AddDate(0, 0, -7)) {
			t.Errorf("a rolling window's file does not state the moment it starts: %s",
				week.Body.String()[:min(300, len(week.Body.String()))])
		}
	})
}
