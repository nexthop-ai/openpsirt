// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// toldAbout reports whether any notification waiting for somebody names this
// text.
func toldAbout(t *testing.T, r *httpapitest.Reach, who, text string) bool {
	t.Helper()
	var waiting struct {
		Items []struct {
			Body string `json:"body"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, who, "/v1/notifications", &waiting)
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
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		hidden := r.Embargoed(t)

		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut, httpapitest.FindingAt("CVE-2026-9999")+"/assignment",
			`{"person":"embargo-reader"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		if !toldAbout(t, r, "embargo-reader", "CVE-2026-9999") {
			t.Error("a private-only reader handed a disclosed finding was not told")
		}

		refused := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, httpapitest.FindingAt(hidden)+"/assignment",
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
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		hidden := r.Embargoed(t)

		for _, team := range []string{
			`{"name":"private-desk","members":["embargo-reader"]}`,
			`{"name":"public-desk","members":["reader"]}`,
		} {
			if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams", team); made.Code != http.StatusCreated {
				t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
			}
		}

		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut, httpapitest.FindingAt("CVE-2026-9999")+"/assignment",
			`{"team":"private-desk"}`); got.Code != http.StatusNoContent {
			t.Errorf("a team of private-only readers handed a disclosed finding answered %d: %s",
				got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, httpapitest.FindingAt(hidden)+"/assignment",
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
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		hidden := r.Embargoed(t)

		// refused is the public-only reader's answer. They can see the product,
		// so the rules and an issue act are refused for the role; an issue act
		// is refused before the issue's name is resolved, so it says nothing
		// about whether the issue exists. Taking work is about one finding, and
		// an undisclosed one is not there for them.
		type ask struct {
			what, method, path, body string
			want, refused            int
		}
		asks := []ask{
			{"listing routing rules", http.MethodGet, "/v1/products/mine/routing-rules", "",
				http.StatusOK, http.StatusForbidden},
			{"previewing a routing rule", http.MethodGet,
				"/v1/products/mine/routing-rules/preview?upstream=libnl", "", http.StatusOK,
				http.StatusForbidden},
			{"rating an issue", http.MethodPost, "/v1/products/mine/issues/" + hidden + "/assessment",
				`{"severity":"critical","reasoning":"Reachable from the management port."}`,
				http.StatusCreated, http.StatusForbidden},
			{"recording exploitation here", http.MethodPost,
				"/v1/products/mine/issues/" + hidden + "/exploited-here",
				`{"known_at":"2026-09-20T14:00:00Z","grounds":"A customer sent captures."}`,
				http.StatusCreated, http.StatusForbidden},
			{"taking work nobody holds", http.MethodPut, httpapitest.FindingAt(hidden) + "/assignment",
				`{"person":"embargo-triager"}`, http.StatusNoContent, http.StatusNotFound},
		}
		for _, each := range asks {
			if got := httpapitest.AsPerson(t, r, "reader", each.method, each.path, each.body); got.Code != each.refused {
				t.Errorf("%s: a public-only reader answered %d, want %d: %s",
					each.what, got.Code, each.refused, got.Body.String())
			}
			if got := httpapitest.AsPerson(t, r, "embargo-triager", each.method, each.path, each.body); got.Code != each.want {
				t.Errorf("%s: private-only triage answered %d, want %d: %s",
					each.what, got.Code, each.want, got.Body.String())
			}
		}
		// The same act on an issue nobody recorded is refused the same way.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodPost,
			"/v1/products/mine/issues/CVE-2099-0001/assessment",
			`{"severity":"critical","reasoning":"Reachable from the management port."}`),
			http.StatusForbidden)
	})
}

// Agreeing is answered at one visibility: reading there, with the approver
// capability or triage there. The session says so per visibility, and the
// approval itself is refused and accepted on the same terms.
func TestAgreeingIsAnsweredAtTheClaimsOwnVisibility(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		hidden := r.Embargoed(t)

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
			httpapitest.Read(t, r, who, "/v1/session/me", &me)
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

		disclosed, _ := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		undisclosed, _ := r.Claimed(t, "private-triage", hidden, "libnl-3-200", httpapitest.Dismissal)

		if got := httpapitest.AsPerson(t, r, "split-triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", disclosed), `{}`); got.Code != http.StatusNotFound {
			t.Errorf("triage of undisclosed work agreeing to a disclosed claim answered %d: %s",
				got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "split-triager", http.MethodPost,
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
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		hidden := r.Embargoed(t)

		// Reachable, so the refusal below is about arguing rather than
		// about reading.
		if got := httpapitest.AsPerson(t, r, "split-triager", http.MethodGet, httpapitest.FindingAt("CVE-2026-9999"), ""); got.Code != http.StatusOK {
			t.Fatalf("reading the disclosed finding answered %d: %s", got.Code, got.Body.String())
		}
		made := httpapitest.AsPerson(t, r, "split-triager", http.MethodPost,
			httpapitest.FindingAt("CVE-2026-9999")+"/decision", httpapitest.Dismissal)
		httpapitest.RefusedWith(t, made, http.StatusNotFound)

		// And arguing about the undisclosed one is theirs.
		if got := httpapitest.AsPerson(t, r, "split-triager", http.MethodPost,
			httpapitest.FindingAt(hidden)+"/decision", httpapitest.Dismissal); got.Code != http.StatusCreated {
			t.Errorf("triage of undisclosed work arguing about an undisclosed finding answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}
