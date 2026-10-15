// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

func TestOnlyPeopleWhoCanAlreadySeeItAreOfferedAsMentions(t *testing.T) {
	// An autocomplete listing everybody teaches somebody to name a colleague
	// who then cannot open what they were called to. On an undisclosed finding
	// it is worse than unhelpful: the mention itself says a finding exists,
	// which is the disclosure the visibility rule is there to prevent.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		type person struct {
			Identity string `json:"identity"`
			Name     string `json:"name"`
		}
		type list struct {
			Items []person `json:"items"`
		}
		has := func(items []person, who string) bool {
			for _, each := range items {
				if each.Identity == who {
					return true
				}
			}
			return false
		}

		// Everybody who can read what has been disclosed.
		var public list
		httpapitest.Read(t, r, "triager", "/v1/products/mine/mentionable", &public)
		if !has(public.Items, "reader") {
			t.Errorf("somebody who can read the product is not offered: %+v", public.Items)
		}
		if has(public.Items, "nothing") {
			t.Error("somebody granted nothing here is offered as a mention")
		}

		// And undisclosed findings are a narrower set. Somebody trusted only
		// with what has been disclosed must not be offered for one that has
		// not — naming them would call them to something they cannot open.
		var private list
		httpapitest.Read(t, r, "private-triage", "/v1/products/mine/mentionable?visibility=private", &private)
		if has(private.Items, "reader") {
			t.Errorf("somebody who reads only disclosed findings is offered on an undisclosed one: %+v",
				private.Items)
		}
		if len(private.Items) == 0 {
			t.Error("nobody at all may be mentioned on an undisclosed finding")
		}

		// A request for who may be told about an undisclosed finding is itself
		// a question about undisclosed findings, so somebody who cannot read
		// them is answered as though the product were not there.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/mentionable?visibility=private", ""); got.Code != http.StatusNotFound {
			t.Errorf("a public triager asked about undisclosed mentions and got %d: %s",
				got.Code, got.Body.String())
		}
	})
}

func TestBeingToldAboutWorkKeepsItOutOfTheDigest(t *testing.T) {
	// the digest carries what nothing else told you. That rests on the key
	// written when somebody is told matching the key read when the digest
	// asks — and the first version of this did not: one side keyed on the
	// name in the request path and the other on the display name from a
	// query, so they never compared equal and the digest repeated every
	// message.
	//
	// So this asserts across the seam rather than round-tripping one side
	// against itself, which is what let that through.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/assignment"
		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut, at,
			`{"person":"reader"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		reader, err := access.NewStore(r.DB.DB).ByIdentity(t.Context(), "reader")
		if err != nil {
			t.Fatal(err)
		}
		told, err := r.DB.DB.NewSelect().Model((*notify.Notification)(nil)).
			Where(`"person_id" = ?`, reader.ID).Where(`"concerns" <> ?`, "").Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if told != 1 {
			t.Fatalf("%d things were recorded as told, want 1", told)
		}

		// The digest reads what it holds and must recognize the same work.
		digest, err := notify.Assemble(t.Context(), r.DB.DB, reader, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range digest.Mine {
			if item.Issue == "CVE-2026-9999" {
				t.Errorf("the digest repeats work its owner was already told about: %+v", item)
			}
		}
	})
}
