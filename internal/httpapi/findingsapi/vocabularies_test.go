// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

type packageKinds struct {
	Items []struct {
		Kind string `json:"kind"`
		Open int    `json:"open"`
	} `json:"items"`
}

func TestAPackageKindOfferedIsOneTheFindingsListFinds(t *testing.T) {
	// The filter offers what this answers, so a kind here that the list's own
	// filter matches nothing for is a choice that empties the list.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)

		for _, at := range []string{
			"/v1/products/mine/findings/package-kinds",
			"/v1/products/mine/findings/package-kinds?stream=master&variant=broadcom",
			"/v1/findings/package-kinds",
		} {
			var got packageKinds
			httpapitest.Read(t, r, "reader", at, &got)
			if len(got.Items) != 1 || got.Items[0].Kind != "deb" || got.Items[0].Open != 1 {
				t.Errorf("%s offered %+v, want the one Debian package with one issue", at, got.Items)
			}
		}

		var listed struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "reader",
			"/v1/products/mine/findings?stream=master&variant=broadcom&ecosystem=deb", &listed)
		if listed.Total != 1 {
			t.Errorf("the list narrowed to the kind offered holds %d rows, want the 1 counted", listed.Total)
		}
	})
}

func TestPackageKindsAnswerOnlyWhatTheReaderMaySee(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)

		// Undisclosed reading alone reads nothing disclosed, so it is offered
		// no kind, and says so with an empty list rather than an absent one.
		got := httpapitest.AsPerson(t, r, "embargo-reader", http.MethodGet,
			"/v1/products/mine/findings/package-kinds", "")
		if got.Code != http.StatusOK || !httpapitest.Contains(got.Body.String(), `"items":[]`) {
			t.Errorf("undisclosed reading alone answered %d: %s", got.Code, got.Body.String())
		}

		// Somebody who reads no finding in the product is refused as the list
		// refuses them.
		for _, at := range []string{"/v1/products/mine/findings", "/v1/products/mine/findings/package-kinds"} {
			httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "admin", http.MethodGet, at, ""),
				http.StatusForbidden)
		}

		var anywhere packageKinds
		httpapitest.Read(t, r, "admin", "/v1/findings/package-kinds", &anywhere)
		if len(anywhere.Items) != 0 {
			t.Errorf("somebody holding nothing was offered %+v", anywhere.Items)
		}
	})
}

type weaknesses struct {
	Items []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Short string `json:"short"`
	} `json:"items"`
}

func TestAWeaknessIsLookedUpByNumberOrByName(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		var found, byName, named weaknesses
		httpapitest.Read(t, r, "reader", "/v1/weaknesses?q=79&limit=5", &found)
		if len(found.Items) != 5 {
			t.Fatalf("a search limited to five found %d", len(found.Items))
		}
		first := found.Items[0]
		if first.ID != "CWE-79" || first.Short != "Cross-site scripting" || first.Name == "" {
			t.Errorf("the number typed came back as %+v", first)
		}

		httpapitest.Read(t, r, "reader", "/v1/weaknesses?q=double+free", &byName)
		if len(byName.Items) == 0 || byName.Items[0].ID != "CWE-415" {
			t.Errorf("a search by name found %+v", byName.Items)
		}

		// Named in the order asked, and one neither list holds comes back
		// with no names rather than being dropped.
		httpapitest.Read(t, r, "reader", "/v1/weaknesses?id=cwe-1321&id=NVD-CWE-Other", &named)
		if len(named.Items) != 2 {
			t.Fatalf("two identifiers named %d", len(named.Items))
		}
		if named.Items[0].ID != "CWE-1321" || named.Items[0].Name == "" || named.Items[0].Short != "" {
			t.Errorf("a rare weakness came back as %+v", named.Items[0])
		}
		if named.Items[1].ID != "NVD-CWE-OTHER" || named.Items[1].Name != "" {
			t.Errorf("a feed's word for no classification came back as %+v", named.Items[1])
		}

		both := httpapitest.AsPerson(t, r, "reader", http.MethodGet, "/v1/weaknesses?id=CWE-79&q=79", "")
		httpapitest.RefusedWith(t, both, http.StatusUnprocessableEntity)
	})
}
