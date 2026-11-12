// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestTheTrailFileEndsWhenItWasAskedFor pins an open period's end to the moment
// the file was asked for, stated in the file as that moment, so a change recorded while it
// is written lies outside the period on every page.
func TestTheTrailFileEndsWhenItWasAskedFor(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		file := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/administration/changes.json", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		if !strings.Contains(file.Body.String(), `"to":"`+time.Now().UTC().Format(time.DateOnly)+"T") {
			t.Errorf("a file asked for no period does not state the moment it ends: %s", file.Body.String()[:min(300, len(file.Body.String()))])
		}
	})
}
