// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// Configuration is the only source of what groups grant (REQ-41), so nothing
// running changes it: not the mappings, and not where roles come from.
func TestNothingRunningChangesWhatGroupsGrant(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		mapped := []access.Mapping{{Group: "leads", Grants: string(access.Administers)}}
		if _, err := r.Rights.ApplyMappings(t.Context(), mapped); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct{ method, path, body string }{
			{http.MethodPost, "/v1/roles/bindings", `{"group":"anybody","role":"admin"}`},
			{http.MethodDelete, "/v1/roles/bindings?group=leads&role=admin", ""},
			{http.MethodPut, "/v1/roles/mode", `{"mode":"direct"}`},
		} {
			got := httpapitest.AsPerson(t, r, "admin", c.method, c.path, c.body)
			if got.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s answered an administrator %d, want 405: %s",
					c.method, c.path, got.Code, got.Body.String())
			}
		}
		held, err := r.Rights.Mappings(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(held, mapped) {
			t.Errorf("the mappings became %+v", held)
		}
	})
}

// The list says where each mapping is held: on a product, which may not be
// declared yet, on every product, or over the deployment.
func TestTheBindingsListSaysWhereEachMappingIsHeld(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if _, err := r.Rights.ApplyMappings(t.Context(), []access.Mapping{
			{Group: "auditors", Grants: string(access.Audits)},
			{Group: "kernel", Grants: string(access.PublicTriage), Product: "mine"},
			{Group: "kernel", Grants: string(access.PublicTriage), Product: "not-yet"},
			{Group: "psirt", Grants: string(access.PrivateRead)},
		}); err != nil {
			t.Fatal(err)
		}
		var listed struct {
			Items []struct {
				Group       string `json:"group"`
				Product     string `json:"product"`
				ProductName string `json:"product_name"`
				Role        string `json:"role"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "admin", "/v1/roles/bindings", &listed)
		type row = struct{ group, product, shown, role string }
		var got []row
		for _, item := range listed.Items {
			got = append(got, row{item.Group, item.Product, item.ProductName, item.Role})
		}
		want := []row{
			{"auditors", "", "", "audit"},
			{"kernel", "mine", "Shown as mine", "public-triage"},
			{"kernel", "not-yet", "", "public-triage"},
			{"psirt", "", "", "private-read"},
		}
		if !slices.Equal(got, want) {
			t.Errorf("listed\n%+v\nwant\n%+v", got, want)
		}
	})
}
