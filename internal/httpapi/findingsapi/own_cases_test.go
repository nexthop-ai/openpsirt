// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/findingsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const ownCases = "/v1/session/me/cases"

// collaborates is whether the session says one person has their own cases to
// ask for.
func collaborates(t *testing.T, r *httpapitest.Reach, who string) bool {
	t.Helper()
	var me struct {
		Collaborates bool `json:"collaborates"`
	}
	httpapitest.Read(t, r, who, "/v1/session/me", &me)
	return me.Collaborates
}

// ownCasesOf is what one person's own cases answer.
func ownCasesOf(t *testing.T, r *httpapitest.Reach, who string) findingsapi.OwnCasesBody {
	t.Helper()
	var body findingsapi.OwnCasesBody
	httpapitest.Read(t, r, who, ownCases, &body)
	return body
}

// A person's own cases are the grants they hold, and nobody else's: a case
// stands until it is withdrawn, and a code finding until it is withdrawn or
// its flaw is disclosed. The session says there are cases to ask for exactly
// where the list holds one.
func TestAPersonListsTheCasesAndCodeFindingsTheyWereGrantedAlone(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		embargoed := r.Embargoed(t)
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)

		if got := ownCasesOf(t, r, "outsider"); len(got.Cases)+len(got.CodeFindings) != 0 {
			t.Fatalf("somebody granted nothing lists %+v", got)
		}
		if collaborates(t, r, "outsider") {
			t.Error("the session says somebody granted nothing has cases to ask for")
		}
		caseAt := "/v1/products/mine/issues/" + embargoed + "/collaborators/outsider"
		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPut, caseAt, ""); got.Code != http.StatusNoContent {
			t.Fatalf("bringing them into the case answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut,
			codeFindingAt(occurrence)+"/collaborators/outsider", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the code finding answered %d: %s", got.Code, got.Body)
		}

		if !collaborates(t, r, "outsider") {
			t.Error("the session says somebody brought into a case has none to ask for")
		}
		got := ownCasesOf(t, r, "outsider")
		if len(got.Cases) != 1 || got.Cases[0].Product != "mine" || got.Cases[0].Issue != embargoed ||
			got.Cases[0].AddedAt == "" {
			t.Errorf("their cases are %+v; want %s in mine", got.Cases, embargoed)
		}
		if len(got.CodeFindings) != 1 {
			t.Fatalf("their code findings are %+v; want the one granted", got.CodeFindings)
		}
		if one := got.CodeFindings[0]; one.Occurrence != occurrence || one.Flaw != flaw || one.Product != "mine" ||
			one.BranchOrTag != "master" || one.Variant != "broadcom" || one.Rule == "" || one.Path != "src/a.c" {
			t.Errorf("their code finding is %+v; want %s, recorded as %s, in mine master broadcom", one, occurrence, flaw)
		}

		// Somebody else's grants are not listed to anybody, including those
		// who read the whole product.
		for _, who := range []string{"reader", "private-triage", "code-finding-handler"} {
			if other := ownCasesOf(t, r, who); len(other.Cases)+len(other.CodeFindings) != 0 {
				t.Errorf("%s lists somebody else's grants: %+v", who, other)
			}
		}

		if got := httpapitest.AsPerson(t, r, "private-triage", http.MethodDelete, caseAt, ""); got.Code != http.StatusNoContent {
			t.Fatalf("taking them off the case answered %d: %s", got.Code, got.Body)
		}
		if got := ownCasesOf(t, r, "outsider"); len(got.Cases) != 0 || len(got.CodeFindings) != 1 {
			t.Errorf("after the case grant was withdrawn they list %+v; want the code finding alone", got)
		}
		codeFindingGrant := codeFindingAt(occurrence) + "/collaborators/outsider"
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete, codeFindingGrant, ""); got.Code != http.StatusNoContent {
			t.Fatalf("taking them off the code finding answered %d: %s", got.Code, got.Body)
		}
		if got := ownCasesOf(t, r, "outsider"); len(got.Cases)+len(got.CodeFindings) != 0 {
			t.Errorf("after both grants were withdrawn they list %+v; want nothing", got)
		}
		if collaborates(t, r, "outsider") {
			t.Error("the session says somebody whose grants were all withdrawn has cases to ask for")
		}

		// A code finding grant outlives its flaw's disclosure and lists
		// nothing, so the session says there is nothing to ask for.
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, codeFindingGrant, ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the code finding again answered %d: %s", got.Code, got.Body)
		}
		if got := ownCasesOf(t, r, "outsider"); len(got.CodeFindings) != 1 || !collaborates(t, r, "outsider") {
			t.Fatalf("granted the code finding again they list %+v; want it, and the session to say so", got)
		}
		disclosed(t, r, flaw)
		if got := ownCasesOf(t, r, "outsider"); len(got.Cases)+len(got.CodeFindings) != 0 {
			t.Errorf("after the flaw was disclosed they list %+v; want nothing", got)
		}
		if collaborates(t, r, "outsider") {
			t.Error("the session says somebody whose one grant is on a disclosed flaw has cases to ask for")
		}
	})
}

// Who may ask for their own cases: every person, and no pipeline.
func TestWhoMayListTheirOwnCases(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, c := range []struct {
			who  string
			want int
		}{
			{"", http.StatusUnauthorized},
			{"outsider", http.StatusOK},
			{"reader", http.StatusOK},
			{"auditor", http.StatusOK},
		} {
			if got := httpapitest.AsPerson(t, r, c.who, http.MethodGet, ownCases, ""); got.Code != c.want {
				t.Errorf("%q GET %s = %d, want %d: %s", c.who, ownCases, got.Code, c.want, got.Body.String())
			}
		}
		if got := r.WithKey(t, r.Key, http.MethodGet, ownCases); got.Code != http.StatusForbidden {
			t.Errorf("a pipeline key read its own cases: %d %s", got.Code, got.Text)
		}
	})
}
