// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const groupsOfMine = "/v1/products/mine/branches-and-tags/master/variants/broadcom/component-groups"

func TestComponentGroupsCountOnlyWhatTheReaderMaySee(t *testing.T) {
	// One issue of two undisclosed, so a count is the disclosure.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set(`"visibility" = ?`, "private").
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`,
				"CVE-2026-1000").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			who, query string
			code, open int
		}{
			{"private", "by=ecosystem", http.StatusOK, 2},
			{"reader", "by=ecosystem", http.StatusOK, 1},
			{"embargo-reader", "by=ecosystem", http.StatusOK, 1},
			{"reader", "by=ecosystem&ecosystem=deb", http.StatusOK, 1},
			{"private", "by=ecosystem&ecosystem=deb", http.StatusOK, 2},
			{"outsider", "by=ecosystem", http.StatusNotFound, -1},
			{"approver", "by=ecosystem", http.StatusNotFound, -1},
			{"", "by=ecosystem", http.StatusUnauthorized, -1},
		} {
			got := httpapitest.AsPerson(t, r, c.who, http.MethodGet, groupsOfMine+"?"+c.query, "")
			open := -1
			if got.Code == http.StatusOK {
				var body struct {
					Items []struct {
						Key  string `json:"key"`
						Open int    `json:"open"`
					} `json:"items"`
				}
				if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				open = 0
				for _, item := range body.Items {
					open += item.Open
				}
			}
			if got.Code != c.code || open != c.open {
				t.Errorf("%q with %s answered %d with %d open, want %d with %d: %s",
					c.who, c.query, got.Code, open, c.code, c.open, got.Body.String())
			}
		}
	})
}

func TestComponentGroupsRefuseAnEcosystemOutsideTheEcosystemList(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		for _, query := range []string{"by=repository&ecosystem=deb", "by=everything", ""} {
			got := httpapitest.AsPerson(t, r, "reader", http.MethodGet, groupsOfMine+"?"+query, "")
			if got.Code != http.StatusUnprocessableEntity {
				t.Errorf("%q answered %d, want 422: %s", query, got.Code, got.Body.String())
			}
		}
	})
}
