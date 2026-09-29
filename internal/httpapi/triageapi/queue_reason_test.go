// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAProposalThatNeedsNobodyIsListedInForceRatherThanWaiting(t *testing.T) {
	// An "affected" answer needs no second person and is in force when made.
	// The findings list reads it as agreed, the way the finding screen reads
	// it, and the waiting filter does not return it.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		at := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/decision", place)
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"affected","reasoning":"We ship the vulnerable parser."}`); got.Code != http.StatusCreated {
			t.Fatalf("recording affected answered %d: %s", got.Code, got.Body.String())
		}
		for state, want := range map[string]int{"waiting": 0, "agreed": 1} {
			var page struct {
				Total int `json:"total"`
			}
			httpapitest.Read(t, r, "triager", "/v1/products/mine/findings?state="+state, &page)
			if page.Total != want {
				t.Errorf("an affected answer is in %d rows under %q, want %d", page.Total, state, want)
			}
		}
	})
}

func TestAMissedFixDateFileSaysWhichDateWasMissed(t *testing.T) {
	// The card on screen reads "Patch by" the date. A file of the same list
	// that dropped the date could not say which promise did not hold.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		at := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/decision", place)
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"patch-needed","committed_to":"`+httpapitest.AheadOfUs+`",`+
				`"reasoning":"Taking the upstream commit as a distro patch."}`); got.Code != http.StatusCreated {
			t.Fatalf("recording a backport answered %d: %s", got.Code, got.Body.String())
		}
		missed := time.Now().UTC().AddDate(0, 0, -3).Truncate(24 * time.Hour)
		if _, err := r.DB.DB.NewUpdate().Table("claim").
			Set("committed_to = ?", missed).
			Where("outcome = ?", "patch-needed").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			"/v1/review-queue.csv?reason=missed-fix-date", "")
		if got.Code != http.StatusOK {
			t.Fatalf("the export answered %d: %s", got.Code, got.Body.String())
		}
		all, err := csv.NewReader(strings.NewReader(got.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := httpapitest.RowsUnder(all)
		if len(body) != 2 {
			t.Fatalf("the missed fix dates file holds %d rows, want the one promise: %v",
				len(body)-1, body)
		}
		column := httpapitest.IndexOf(body[0], "committed to")
		if column < 0 {
			t.Fatalf("the file has no committed to column: %v", body[0])
		}
		if want := missed.Format(time.DateOnly); body[1][column] != want {
			t.Errorf("the file says the promise was for %q, want %q", body[1][column], want)
		}
	})
}
