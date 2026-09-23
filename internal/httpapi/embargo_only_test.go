// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"testing"
)

// Somebody working private reports holds the undisclosed half alone, and is
// not handed the disclosed stream with it. Each visibility is its own grant,
// and this is the identity the two private-only roles exist for.
func TestTheUndisclosedHalfAloneReadsNothingDisclosed(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		hidden := r.embargoed(t)

		// The product's own list, and the two that span products, which
		// narrow through a different path.
		lists := []string{"/v1/products/mine/findings", "/v1/findings", "/v1/unassigned"}
		listed := func(t *testing.T, who, path string) map[string]bool {
			t.Helper()
			var out struct {
				Items []struct {
					Vulnerability string `json:"vulnerability"`
				} `json:"items"`
			}
			read(t, r, who, path, &out)
			seen := map[string]bool{}
			for _, item := range out.Items {
				seen[item.Vulnerability] = true
			}
			return seen
		}
		for _, path := range lists {
			for _, who := range []string{"embargo-reader", "embargo-triager"} {
				seen := listed(t, who, path)
				if !seen[hidden] {
					t.Errorf("%s: %s does not read the undisclosed finding: %v", path, who, seen)
				}
				if seen["CVE-2026-9999"] {
					t.Errorf("%s: %s reads a disclosed finding it holds no grant for: %v",
						path, who, seen)
				}
			}
			// The pair the rest of the suite leans on, so the absence above
			// is the grant rather than the list being empty.
			if seen := listed(t, "private", path); !seen[hidden] || !seen["CVE-2026-9999"] {
				t.Errorf("%s: a reader of both halves does not read both: %v", path, seen)
			}
		}

		var who struct {
			Reach []struct {
				Product       string `json:"product"`
				MaySee        bool   `json:"may_see"`
				ReadsPublic   bool   `json:"reads_public"`
				ReadsPrivate  bool   `json:"reads_private"`
				MayTriage     bool   `json:"may_triage"`
				TriagesPublic bool   `json:"triages_public"`
				MayHide       bool   `json:"may_hide"`
			} `json:"reach"`
		}
		read(t, r, "embargo-triager", "/v1/session/me", &who)
		if len(who.Reach) != 1 {
			t.Fatalf("the session reaches %d products, want the one granted", len(who.Reach))
		}
		if can := who.Reach[0]; !can.MaySee || can.ReadsPublic || !can.ReadsPrivate ||
			!can.MayTriage || can.TriagesPublic || !can.MayHide {
			t.Errorf("the session describes private triage as %+v", can)
		}

		// Arguing about the disclosed finding is refused: the product is one
		// they triage in, and the finding is not one they may read.
		made := asPerson(t, r, "embargo-triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+place+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"The parser is never reached."}`)
		if made.Code < 400 || made.Code >= 500 {
			t.Errorf("private triage argued about a disclosed finding: %d %s",
				made.Code, made.Body.String())
		}

		// Handed a disclosed finding, they see it: an assignment carries a
		// disclosed row to whoever holds it, whatever they read.
		if got := asPerson(t, r, "assigner", http.MethodPut, findingAt("CVE-2026-9999")+"/assignment",
			`{"person":"embargo-reader"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		if seen := listed(t, "embargo-reader", "/v1/people/me/assignments"); !seen["CVE-2026-9999"] {
			t.Errorf("a disclosed finding handed to a private-only reader is not theirs to see: %v",
				seen)
		}

		// Recording a flaw that is already public asks for the public half.
		if got := asPerson(t, r, "embargo-triager", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"disclosed":true,`+
				`"summary":"A flaw somebody announced last week.",`+
				`"severity":"high","component":"libnl-3-200"}`); got.Code < 400 || got.Code >= 500 {
			t.Errorf("private triage recorded a disclosed flaw: %d %s", got.Code, got.Body.String())
		}
	})
}
