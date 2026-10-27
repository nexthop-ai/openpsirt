// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTheFileOfYourDecisionsHoldsWhatTheMineTabLists(t *testing.T) {
	// The Mine tab lists every decision its reader proposed, whatever became of
	// it. The queue's own file with mine set holds only what still waits, so
	// an approved decision is on the tab and missing from that file.
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

		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decision), `{}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}

		mine := file("triager", "/v1/my-decisions.csv")
		if len(mine) != 2 {
			t.Fatalf("the proposer's file of their decisions has %d rows, want the one: %v",
				len(mine)-1, mine)
		}
		became := httpapitest.IndexOf(mine[0], "became")
		if became < 0 || mine[1][became] != "approved" {
			t.Errorf("the decision is filed as %v, want it approved", mine[1])
		}
		if waiting := file("triager", "/v1/review-queue.csv?mine=true"); len(waiting) != 1 {
			t.Errorf("the queue's own file still holds the approved decision: %v", waiting)
		}
		for _, column := range []string{"stream", "variant"} {
			if at := httpapitest.IndexOf(mine[0], column); at < 0 || mine[1][at] == "" {
				t.Errorf("the decision's row names no %s, which the tab shows: %v", column, mine)
			}
		}
		if theirs := file("reviewer", "/v1/my-decisions.csv"); len(theirs) != 1 {
			t.Errorf("somebody who proposed nothing exported %v", theirs)
		}

		// A proposer who has lost the product keeps the file and loses the
		// decision's row: what they proposed there is no longer theirs to read.
		// They keep a role on the other product, so they are still somebody
		// signed in.
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"triager","holds":[{"product":"theirs","role":"public-read"}]}`); got.Code >= 300 {
			t.Fatalf("granting the triager the other product answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/triager/roles/mine/public-triage", ""); got.Code >= 300 {
			t.Fatalf("withdrawing the triager's role answered %d: %s", got.Code, got.Body.String())
		}
		if lost := file("triager", "/v1/my-decisions.csv"); len(lost) != 1 {
			t.Errorf("a proposer who lost the product still exports its decision: %v", lost)
		}
	})
}
