// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestRecordingSomebodyRefusesAHoldItCannotPlace(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, c := range []struct{ what, body, says string }{
			{"a role held on one product and everywhere at once",
				`{"identity":"both-ways","holds":[{"role":"public-read","everywhere":true,"product":"mine"}]}`,
				"not both"},
			{"a role held on no product and not everywhere",
				`{"identity":"nowhere","holds":[{"role":"public-read"}]}`,
				"say which product"},
		} {
			got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/people", c.body)
			httpapitest.RefusedWith(t, got, http.StatusUnprocessableEntity)
			if !strings.Contains(got.Body.String(), c.says) {
				t.Errorf("%s was refused as %s", c.what, got.Body.String())
			}
		}
		// Nothing of either was written, the estate grant included.
		var listed struct {
			Items []struct {
				Identity string `json:"identity"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "admin", "/v1/people", &listed)
		for _, one := range listed.Items {
			if one.Identity == "both-ways" || one.Identity == "nowhere" {
				t.Errorf("a refused record left %s recorded", one.Identity)
			}
		}
	})
}

func TestWithdrawingARoleNamesARoleSomebodyHolds(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, c := range []struct {
			what, path string
			want       int
		}{
			{"a word that is not a role", "/v1/people/reader/roles/mine/no-such-role",
				http.StatusUnprocessableEntity},
			{"a role they do not hold", "/v1/people/reader/roles/mine/private-triage",
				http.StatusNotFound},
			{"a word that is not a role, everywhere", "/v1/people/reader/roles/no-such-role",
				http.StatusUnprocessableEntity},
			{"a role they do not hold everywhere", "/v1/people/reader/roles/public-read",
				http.StatusNotFound},
		} {
			got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, c.path, "")
			if got.Code != c.want {
				t.Errorf("withdrawing %s answered %d, want %d: %s", c.what, got.Code, c.want,
					got.Body.String())
			}
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "admin", http.MethodGet,
			"/v1/people?role=no-such-role", ""), http.StatusUnprocessableEntity)
	})
}
