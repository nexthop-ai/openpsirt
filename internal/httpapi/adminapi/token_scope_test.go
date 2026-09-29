// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A personal token may be narrowed to one product when it is made, and the
// narrowing intersects rather than adds: pinning it to something its owner
// cannot read reaches nothing rather than granting it.
//
// All of this was implemented and none of it could be asked for — the one
// screen that mints a token sent only a name and a lifetime.
func TestAPersonalTokenIsNarrowedWhenItIsMade(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		made := httpapitest.AsPerson(t, r, "private", http.MethodPost, "/v1/tokens",
			`{"name":"nightly","lifetime":"24h","product":"mine"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("minting a narrowed token answered %d: %s", made.Code, made.Body.String())
		}

		listed := httpapitest.AsPerson(t, r, "private", http.MethodGet, "/v1/tokens", "")
		if listed.Code != http.StatusOK {
			t.Fatalf("listing tokens answered %d", listed.Code)
		}
		var out struct {
			Items []struct {
				Name               string `json:"name"`
				Product            string `json:"product"`
				ProductDisplayName string `json:"product_name"`
				Withdrawn          bool   `json:"withdrawn"`
			} `json:"items"`
		}
		if err := json.Unmarshal(listed.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, listed.Body.String())
		}
		// The address, in the field minting resolves. This asserted the
		// display name, with a comment saying an answer shows what a person
		// reads — which is true of a field beside it and not of this one: a
		// product declared "acme-router" and displayed "Acme Router" was
		// listed under a word that matches no row, so a token could not be
		// remade from what the list said it covered.
		if len(out.Items) != 1 || out.Items[0].Product != "mine" {
			t.Fatalf("the narrowing is not read back as the name that resolves it: %s",
				listed.Body.String())
		}
		// And what a person reads, beside it.
		if out.Items[0].ProductDisplayName != httpapitest.ShownAs("mine") {
			t.Errorf("the listing does not say what to call the product: %s",
				listed.Body.String())
		}
	})
}

// Withdrawing marks rather than deletes, so that what used a token stays
// answerable. The row therefore stays in the listing, and it has to say it has
// been withdrawn — otherwise pressing Withdraw changes nothing anybody can
// see, which is what it did.
func TestAWithdrawnTokenIsStillListedAndSaysSo(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if made := httpapitest.AsPerson(t, r, "private", http.MethodPost, "/v1/tokens",
			`{"name":"nightly","lifetime":"24h"}`); made.Code != http.StatusCreated {
			t.Fatalf("minting answered %d: %s", made.Code, made.Body.String())
		}
		if gone := httpapitest.AsPerson(t, r, "private", http.MethodDelete, "/v1/tokens/nightly", ""); gone.Code != http.StatusNoContent &&
			gone.Code != http.StatusOK {
			t.Fatalf("withdrawing answered %d: %s", gone.Code, gone.Body.String())
		}

		listed := httpapitest.AsPerson(t, r, "private", http.MethodGet, "/v1/tokens", "")
		var out struct {
			Items []struct {
				Name      string `json:"name"`
				Withdrawn bool   `json:"withdrawn"`
			} `json:"items"`
		}
		if err := json.Unmarshal(listed.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, listed.Body.String())
		}
		if len(out.Items) != 1 {
			t.Fatalf("a withdrawn token left the listing, so nothing records what used it")
		}
		if !out.Items[0].Withdrawn {
			t.Error("a withdrawn token is not reported as withdrawn, so withdrawing looks like nothing")
		}
	})
}

// A withdrawal of something already withdrawn, or never there, is not found,
// and leaves no row in the trail. Answered as success, it records a withdrawal
// that did not happen.
func TestAWithdrawalThatMatchesNothingIsNotFoundAndRecordsNothing(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if made := httpapitest.AsPerson(t, r, "private", http.MethodPost, "/v1/tokens",
			`{"name":"nightly","lifetime":"24h"}`); made.Code != http.StatusCreated {
			t.Fatalf("minting answered %d: %s", made.Code, made.Body.String())
		}
		if gone := httpapitest.AsPerson(t, r, "private", http.MethodDelete, "/v1/tokens/nightly", ""); gone.Code >= 300 {
			t.Fatalf("withdrawing answered %d: %s", gone.Code, gone.Body.String())
		}
		// Recorded, with no identifier pinned.
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/people",
			`{"identity":"unpinned"}`); made.Code >= 300 {
			t.Fatalf("recording answered %d: %s", made.Code, made.Body.String())
		}

		var before httpapitest.Changed
		httpapitest.Read(t, r, "admin", "/v1/administration/changes?limit=1", &before)
		for _, again := range []struct{ who, what, path string }{
			{"private", "their own token, withdrawn again", "/v1/tokens/nightly"},
			{"admin", "somebody's token, withdrawn again", "/v1/people/private/tokens/nightly"},
			{"admin", "an identifier nobody pinned", "/v1/people/unpinned/identifier"},
		} {
			if got := httpapitest.AsPerson(t, r, again.who, http.MethodDelete, again.path, ""); got.Code != http.StatusNotFound {
				t.Errorf("%s answered %d, want 404: %s", again.what, got.Code, got.Body.String())
			}
		}
		var after httpapitest.Changed
		httpapitest.Read(t, r, "admin", "/v1/administration/changes?limit=1", &after)
		if after.Total != before.Total {
			t.Errorf("withdrawals that matched nothing left %d rows in the trail",
				after.Total-before.Total)
		}
	})
}
