// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTheFileOfYourClaimsHoldsWhatTheMineTabLists(t *testing.T) {
	// The Mine tab lists every claim its reader proposed, whatever became of
	// it. The queue's own file with mine set holds only what still waits, so
	// an approved claim is on the tab and missing from that file.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		file := func(who, at string) [][]string {
			t.Helper()
			got := httpapitest.AsPerson(t, r, who, http.MethodGet, at, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s exporting %s answered %d: %s", who, at, got.Code, got.Body.String())
			}
			read, err := csv.NewReader(strings.NewReader(got.Body.String())).ReadAll()
			if err != nil {
				t.Fatalf("%s is not a spreadsheet: %v", at, err)
			}
			return httpapitest.RowsUnder(read)
		}

		claim, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}

		mine := file("triager", "/v1/my-claims.csv")
		if len(mine) != 2 {
			t.Fatalf("the proposer's file of their claims has %d rows, want the one: %v",
				len(mine)-1, mine)
		}
		became := httpapitest.IndexOf(mine[0], "became")
		if became < 0 || mine[1][became] != "approved" {
			t.Errorf("the claim is filed as %v, want it approved", mine[1])
		}
		if waiting := file("triager", "/v1/review-queue.csv?mine=true"); len(waiting) != 1 {
			t.Errorf("the queue's own file still holds the approved claim: %v", waiting)
		}
		if theirs := file("reviewer", "/v1/my-claims.csv"); len(theirs) != 1 {
			t.Errorf("somebody who proposed nothing exported %v", theirs)
		}
	})
}
