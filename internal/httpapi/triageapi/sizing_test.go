// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTheCandidateListSaysHowFarAClaimWouldReach(t *testing.T) {
	// The bound on a bulk action is on rows written rather than on names
	// typed, and the screen counted issues — so somebody narrowing 805
	// candidates was told 805 and refused at 22,000, after typing the
	// reasoning.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// One library under two consumers, so an issue sits at two places:
		// the case where "how many issues" and "how many findings" are
		// different numbers, which is the whole of what this is about.
		r.ScannedShared(t)

		var page struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Places        int    `json:"places"`
			} `json:"items"`
			Total      int `json:"total"`
			Findings   int `json:"findings"`
			IssueLimit int `json:"issue_limit"`
			PlaceLimit int `json:"place_limit"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libyang/issues", &page)
		if page.Total != 2 || len(page.Items) != 2 {
			t.Fatalf("the component holds %d issues, want its two", page.Total)
		}
		// The two numbers are not the same number, which is the defect: each
		// issue sits at two places.
		if page.Findings == page.Total {
			t.Fatalf("%d issues and %d findings, so this fixture cannot tell them apart",
				page.Total, page.Findings)
		}
		// The two numbers a claim is sized by, and they are not the same
		// number: two issues, and however many findings those sit at.
		want := 0
		for _, each := range page.Items {
			want += each.Places
		}
		if page.Findings != want {
			t.Errorf("the list says %d findings and its rows add to %d", page.Findings, want)
		}
		if page.IssueLimit <= 0 || page.PlaceLimit <= 0 {
			t.Error("the list does not say what the limits on one action are")
		}

		// And both numbers are over the whole narrowed set rather than over the
		// page: narrowing to a term nothing matches takes both to nothing.
		var narrowed struct {
			Total    int `json:"total"`
			Findings int `json:"findings"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libyang/issues?contains=nothing-says-this", &narrowed)
		if narrowed.Total != 0 || narrowed.Findings != 0 {
			t.Errorf("a term nothing matches leaves %d issues and %d findings",
				narrowed.Total, narrowed.Findings)
		}
	})
}
