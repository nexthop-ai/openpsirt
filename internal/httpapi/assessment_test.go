// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A rating waiting for a second person says whether that person is you.
//
// The server refuses your own either way, so what this buys is a screen that
// says so rather than one offering a button that answers 422: the embargo
// extensions listed beside these in the review queue already carry the same
// field, and this one did not.
func TestARatingSaysWhetherItIsYourOwn(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		// Milder than what was published, which is the direction that waits.
		made := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/issues/CVE-2026-9999/assessment",
			`{"severity":"low","reasoning":"Not reachable in how we build it."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording a rating answered %d: %s", made.Code, made.Body.String())
		}
		var claim struct {
			ID            int64 `json:"id"`
			NeedsApproval bool  `json:"needs_approval"`
			Mine          bool  `json:"mine"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &claim); err != nil {
			t.Fatal(err)
		}
		if !claim.NeedsApproval {
			t.Fatal("a milder rating needed nobody, so this tests nothing")
		}
		if !claim.Mine {
			t.Error("the rating you just made does not read as yours")
		}

		mine := func(who string) bool {
			t.Helper()
			var page struct {
				Items []struct {
					ID   int64 `json:"id"`
					Mine bool  `json:"mine"`
				} `json:"items"`
			}
			got := asPerson(t, r, who, http.MethodGet, "/v1/assessments?state=proposed", "")
			if got.Code != http.StatusOK {
				t.Fatalf("listing as %s answered %d: %s", who, got.Code, got.Body.String())
			}
			if err := json.Unmarshal(got.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			for _, row := range page.Items {
				if row.ID == claim.ID {
					return row.Mine
				}
			}
			t.Fatalf("%s cannot see the rating at all, so this tests nothing", who)
			return false
		}
		if !mine("triager") {
			t.Error("the person who made it is not told it is theirs")
		}
		if mine("reviewer") {
			t.Error("somebody else's rating reads as their own, so the screen would refuse to " +
				"offer the one action they are there for")
		}
	})
}

func TestRatingAnIssueAsksForTriageOnTheProductInThePath(t *testing.T) {
	// The endpoint half of the rule the store holds. A rating moves that
	// product's deadlines and its triage line, so the role is asked for on the
	// product the path names — and a product somebody holds nothing on answers
	// as one that is not declared, before the issue name is looked at.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		const rating = `{"severity":"critical","reasoning":"Reachable in how we ship it."}`
		const here = "/v1/products/mine/issues/CVE-2026-9999/assessment"
		const there = "/v1/products/theirs/issues/CVE-2026-9999/assessment"

		for _, each := range []struct {
			who  string
			path string
			want int
		}{
			// Triage on the product named, which is what it asks for.
			{"triager", here, http.StatusCreated},
			// Reading it is not enough.
			{"reader", here, http.StatusForbidden},
			{"private", here, http.StatusForbidden},
			// The capability with no triage right under it.
			{"approver", here, http.StatusNotFound},
			// Triage somewhere else, which is not triage here.
			{"triager", there, http.StatusNotFound},
			{"", here, http.StatusUnauthorized},
		} {
			got := asPerson(t, r, each.who, http.MethodPost, each.path, rating)
			if got.Code != each.want {
				t.Errorf("%q rating through %s answered %d, want %d: %s",
					each.who, each.path, got.Code, each.want, got.Body.String())
			}
		}
	})
}

func TestAnIssueNotInThisProductCannotBeRatedThroughIt(t *testing.T) {
	// A name nobody has used and a name for an issue this product does not
	// carry answer alike, so a rating route cannot be walked to find out which
	// issues a product ships.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		const rating = `{"severity":"critical","reasoning":"Reachable in how we ship it."}`
		for _, name := range []string{"CVE-2026-9999", "CVE-2026-0000"} {
			got := asPerson(t, r, "wide-triager", http.MethodPost,
				"/v1/products/theirs/issues/"+name+"/assessment", rating)
			if got.Code != http.StatusNotFound {
				t.Errorf("rating %s in a product that does not carry it answered %d, want the "+
					"words an unused name gets: %s", name, got.Code, got.Body.String())
			}
		}
	})
}
