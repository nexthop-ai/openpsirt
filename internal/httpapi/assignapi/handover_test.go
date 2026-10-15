// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// An upgrade handed to a person carries visibility of everything the promise
// covers, so one undisclosed finding among them makes the handover a
// disclosure to somebody who may not read undisclosed work, and it is refused.
// A team whose members read nothing on the product is refused for the same
// reason: the work would sit in a queue none of them can see.
//
// Verified by deleting the `if !reads` refusal under `strictest ==
// access.Private` in carrying, and the one after teamMayHold: the embargoed
// and the unreadable-team cases then answer 201.
func TestAnUpgradeIsNotHandedToSomebodyWhoMayNotReadWhatItCovers(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		const at = "/v1/products/mine/components/libnl-3-200/upgrade"
		plan := func(holder string) *httptest.ResponseRecorder {
			return httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, at,
				`{"to":"3.9.0","by":"`+httpapitest.AheadOfUs+`",`+
					`"reasoning":"Taking the 3.9.0 bump in the next build.",`+
					holder+
					`"builds":[{"stream":"master","variant":"broadcom"}]}`)
		}
		var waiting struct {
			Items []struct {
				HeldBy     string `json:"held_by"`
				HeldByName string `json:"held_by_name"`
			} `json:"items"`
		}
		pending := func() int {
			waiting.Items = nil
			httpapitest.Read(t, r, "private-dispatcher",
				"/v1/products/mine/streams/master/variants/broadcom/pending-upgrades", &waiting)
			return len(waiting.Items)
		}

		// A team whose only member reads nothing on this product.
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"outside","display_name":"Outside","members":["auditor"]}`); made.Code >= 300 {
			t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
		}
		httpapitest.RefusedWith(t, plan(`"team":"outside",`), http.StatusUnprocessableEntity)

		// One undisclosed finding on the component, and handing the upgrade
		// to somebody who reads disclosed work alone is refused, with
		// nothing recorded.
		r.Embargoed(t)
		httpapitest.RefusedWith(t, plan(`"person":"reader",`), http.StatusUnprocessableEntity)
		if n := pending(); n != 0 {
			t.Errorf("a refused handover recorded a promise: %d pending", n)
		}

		// Somebody who reads undisclosed work may carry the same set.
		got := plan(`"person":"private",`)
		if got.Code != http.StatusCreated {
			t.Fatalf("handing an undisclosed upgrade to a private reader answered %d: %s",
				got.Code, got.Body.String())
		}
		var done struct {
			Held int `json:"held"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		if done.Held == 0 {
			t.Fatalf("the promise was recorded and nothing was handed over: %s", got.Body.String())
		}
		// Carried by them: addressed by their identity, with the name every
		// other screen shows beside it.
		if n := pending(); n != 1 || waiting.Items[0].HeldBy != "private" ||
			waiting.Items[0].HeldByName != httpapitest.ShownAs("private") {
			t.Errorf("the upgrade handed over reads as %+v, want one held by %q, shown as %q",
				waiting.Items, "private", httpapitest.ShownAs("private"))
		}
	})
}
