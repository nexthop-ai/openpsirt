// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// familyOf is how many items a list of held work answers one reader, how many
// of them are code findings, and the total it states.
func familyOf(t *testing.T, r *httpapitest.Reach, who, path string) (items, code, total int) {
	t.Helper()
	var got struct {
		Items []struct {
			Occurrence string `json:"occurrence"`
		} `json:"items"`
		Total int `json:"total"`
	}
	httpapitest.Read(t, r, who, path, &got)
	for _, item := range got.Items {
		if item.Occurrence != "" {
			code++
		}
	}
	return len(got.Items), code, got.Total
}

// Each list of held work keeps one family where it is asked, and its total
// then counts that family alone: a screen draws two counts, never their sum.
func TestEachFamilyOfHeldWorkIsListedAndCountedApart(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		const who = "code-finding-handler"
		for _, c := range []struct {
			path               string
			items, code, total int
		}{
			{"/v1/unassigned", 4, 3, 4},
			{"/v1/unassigned?family=dependency", 1, 0, 1},
			{"/v1/unassigned?family=code", 3, 3, 3},
		} {
			if items, code, total := familyOf(t, r, who, c.path); items != c.items || code != c.code || total != c.total {
				t.Errorf("%s lists %d items, %d of them code findings, of %d; want %d, %d of %d",
					c.path, items, code, total, c.items, c.code, c.total)
			}
		}

		granted(t, r, who, access.PublicTriage)
		const build = "/v1/products/mine/branches-and-tags/master/variants/broadcom"
		if got := httpapitest.AsPerson(t, r, who, http.MethodPut,
			build+"/findings/CVE-2026-4242/components/libmine1/assignment",
			`{"person":"`+who+`"}`); got.Code != http.StatusNoContent {
			t.Fatalf("taking the dependency finding answered %d: %s", got.Code, got.Body)
		}
		var queue struct {
			Items []struct {
				Occurrence  string `json:"occurrence"`
				BranchOrTag string `json:"branch_or_tag"`
				Variant     string `json:"variant"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, who, "/v1/products/mine/code-findings", &queue)
		if len(queue.Items) == 0 {
			t.Fatal("the hub's build lists no code finding to take")
		}
		if got := httpapitest.AsPerson(t, r, who, http.MethodPut,
			build+"/code-findings/"+queue.Items[0].Occurrence+"/assignment",
			`{"person":"`+who+`"}`); got.Code != http.StatusNoContent {
			t.Fatalf("taking the code finding answered %d: %s", got.Code, got.Body)
		}
		for _, c := range []struct {
			path               string
			items, code, total int
		}{
			{"/v1/people/me/assignments", 2, 1, 2},
			{"/v1/people/me/assignments?family=dependency", 1, 0, 1},
			{"/v1/people/me/assignments?family=code", 1, 1, 1},
			{"/v1/people/" + who + "/assignments?family=code", 1, 1, 1},
			{"/v1/unassigned?family=code", 2, 2, 2},
			{"/v1/unassigned?family=dependency", 0, 0, 0},
		} {
			if items, code, total := familyOf(t, r, who, c.path); items != c.items || code != c.code || total != c.total {
				t.Errorf("%s lists %d items, %d of them code findings, of %d; want %d, %d of %d",
					c.path, items, code, total, c.items, c.code, c.total)
			}
		}
		// A reader of the disclosed half alone is counted no code finding in
		// either family's list.
		if items, code, total := familyOf(t, r, "reader", "/v1/unassigned?family=code"); items != 0 || code != 0 || total != 0 {
			t.Errorf("a reader of disclosed work is listed %d code findings of %d", items, total)
		}
		if got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/unassigned?family=both", ""); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a family nothing declares answered %d; want 422", got.Code)
		}
	})
}
