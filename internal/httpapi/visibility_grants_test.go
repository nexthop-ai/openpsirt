// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// toldAbout reports whether any notification waiting for somebody names this
// text.
func toldAbout(t *testing.T, r *reach, who, text string) bool {
	t.Helper()
	var waiting struct {
		Items []struct {
			Body string `json:"body"`
		} `json:"items"`
	}
	read(t, r, who, "/v1/notifications", &waiting)
	for _, item := range waiting.Items {
		if strings.Contains(item.Body, text) {
			return true
		}
	}
	return false
}

// A disclosed finding assigned to somebody who reads the product at either
// visibility is announced to them, and an undisclosed one is announced only
// to somebody who reads undisclosed work.
func TestAnAssignmentIsAnnouncedToWhoeverMayReadWhatWasAssigned(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := r.embargoed(t)

		if got := asPerson(t, r, "assigner", http.MethodPut, findingAt("CVE-2026-9999")+"/assignment",
			`{"person":"embargo-reader"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		if !toldAbout(t, r, "embargo-reader", "CVE-2026-9999") {
			t.Error("a private-only reader handed a disclosed finding was not told")
		}

		refused := asPerson(t, r, "private-dispatcher", http.MethodPut, findingAt(hidden)+"/assignment",
			`{"person":"reader"}`)
		if refused.Code != http.StatusUnprocessableEntity {
			t.Errorf("handing undisclosed work to a public-only reader answered %d: %s",
				refused.Code, refused.Body.String())
		}
		if toldAbout(t, r, "reader", hidden) {
			t.Error("a public-only reader was told about an undisclosed finding")
		}
	})
}

// A team may hold work when one of its members reads it. Disclosed work
// travels with the assignment, so a member reading undisclosed work alone is
// enough for it; undisclosed work needs a member who reads undisclosed work.
func TestATeamHoldsWhatOneOfItsMembersMayRead(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := r.embargoed(t)

		for _, team := range []string{
			`{"name":"private-desk","members":["embargo-reader"]}`,
			`{"name":"public-desk","members":["reader"]}`,
		} {
			if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams", team); made.Code != http.StatusCreated {
				t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
			}
		}

		if got := asPerson(t, r, "assigner", http.MethodPut, findingAt("CVE-2026-9999")+"/assignment",
			`{"team":"private-desk"}`); got.Code != http.StatusNoContent {
			t.Errorf("a team of private-only readers handed a disclosed finding answered %d: %s",
				got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "private-dispatcher", http.MethodPut, findingAt(hidden)+"/assignment",
			`{"team":"public-desk"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a team of public-only readers handed an undisclosed finding answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}

// A right asked of the product as a whole is triage at either visibility, so
// somebody triaging undisclosed work alone holds it and somebody who only
// reads does not.
func TestProductWideTriageIsHeldByTheUndisclosedHalfAlone(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := r.embargoed(t)

		type ask struct {
			what, method, path, body string
			want                     int
		}
		asks := []ask{
			{"listing routing rules", http.MethodGet, "/v1/products/mine/routing-rules", "",
				http.StatusOK},
			{"previewing a routing rule", http.MethodGet,
				"/v1/products/mine/routing-rules/preview?upstream=libnl", "", http.StatusOK},
			{"rating an issue", http.MethodPost, "/v1/products/mine/issues/" + hidden + "/assessment",
				`{"severity":"critical","reasoning":"Reachable from the management port."}`,
				http.StatusCreated},
			{"recording exploitation here", http.MethodPost,
				"/v1/products/mine/issues/" + hidden + "/exploited-here",
				`{"known_at":"2026-09-20T14:00:00Z","grounds":"A customer sent captures."}`,
				http.StatusCreated},
			{"taking work nobody holds", http.MethodPut, findingAt(hidden) + "/assignment",
				`{"person":"embargo-triager"}`, http.StatusNoContent},
		}
		for _, each := range asks {
			if got := asPerson(t, r, "reader", each.method, each.path, each.body); got.Code < 400 || got.Code >= 500 {
				t.Errorf("%s: a public-only reader answered %d: %s", each.what, got.Code, got.Body.String())
			}
			if got := asPerson(t, r, "embargo-triager", each.method, each.path, each.body); got.Code != each.want {
				t.Errorf("%s: private-only triage answered %d, want %d: %s",
					each.what, got.Code, each.want, got.Body.String())
			}
		}
	})
}

// Agreeing is answered at one visibility: reading there, with the approver
// capability or triage there. The session says so per visibility, and the
// approval itself is refused and accepted on the same terms.
func TestAgreeingIsAnsweredAtTheClaimsOwnVisibility(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := r.embargoed(t)

		type can struct {
			MayAgree      bool `json:"may_agree"`
			AgreesPublic  bool `json:"agrees_public"`
			AgreesPrivate bool `json:"agrees_private"`
		}
		session := func(who string) can {
			t.Helper()
			var me struct {
				Reach []struct {
					Product string `json:"product"`
					can
				} `json:"reach"`
			}
			read(t, r, who, "/v1/session/me", &me)
			for _, each := range me.Reach {
				if each.Product == "mine" {
					return each.can
				}
			}
			t.Fatalf("the session of %s does not reach the product", who)
			return can{}
		}
		for who, want := range map[string]can{
			"split-triager":  {MayAgree: true, AgreesPublic: false, AgreesPrivate: true},
			"reviewer":       {MayAgree: true, AgreesPublic: true, AgreesPrivate: false},
			"embargo-reader": {MayAgree: false, AgreesPublic: false, AgreesPrivate: false},
			"private-triage": {MayAgree: true, AgreesPublic: true, AgreesPrivate: true},
		} {
			if got := session(who); got != want {
				t.Errorf("the session describes %s's agreeing as %+v, want %+v", who, got, want)
			}
		}

		disclosed, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		undisclosed, _ := r.claimed(t, "private-triage", hidden, "libnl-3-200", dismissal)

		if got := asPerson(t, r, "split-triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", disclosed), `{}`); got.Code < 400 || got.Code >= 500 {
			t.Errorf("triage of undisclosed work agreed to a disclosed claim: %d %s",
				got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "split-triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", undisclosed), `{}`); got.Code != http.StatusOK {
			t.Errorf("triage of undisclosed work agreeing to an undisclosed claim answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}

// Arguing is asked at the finding's own visibility. Somebody who reads a
// disclosed finding and triages only undisclosed work in the same product
// reaches the finding and is refused the argument about it.
func TestArguingIsAskedAtTheFindingsOwnVisibility(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		hidden := r.embargoed(t)

		// Reachable, so the refusal below is about arguing rather than
		// about reading.
		if got := asPerson(t, r, "split-triager", http.MethodGet, findingAt("CVE-2026-9999"), ""); got.Code != http.StatusOK {
			t.Fatalf("reading the disclosed finding answered %d: %s", got.Code, got.Body.String())
		}
		made := asPerson(t, r, "split-triager", http.MethodPost,
			findingAt("CVE-2026-9999")+"/decision", dismissal)
		if made.Code < 400 || made.Code >= 500 {
			t.Errorf("triage of undisclosed work argued about a disclosed finding: %d %s",
				made.Code, made.Body.String())
		}

		// And arguing about the undisclosed one is theirs.
		if got := asPerson(t, r, "split-triager", http.MethodPost,
			findingAt(hidden)+"/decision", dismissal); got.Code != http.StatusCreated {
			t.Errorf("triage of undisclosed work arguing about an undisclosed finding answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}
