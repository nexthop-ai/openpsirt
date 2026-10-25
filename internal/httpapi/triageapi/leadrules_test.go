// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

const leadRulesAt = "/v1/products/mine/lead-rules"

// leadRuleRead is a standing rule as somebody reads it.
type leadRuleRead struct {
	ID       int64  `json:"id"`
	Rule     string `json:"rule"`
	Prefix   string `json:"prefix"`
	Approved *int   `json:"approved_covering"`
	Covering int    `json:"covering"`
	State    string `json:"state"`
}

func proposeLeadRule(t *testing.T, r *httpapitest.Reach, body string) leadRuleRead {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadRulesAt, body)
	if got.Code != http.StatusCreated {
		t.Fatalf("proposing %s answered %d: %s", body, got.Code, got.Body)
	}
	var rule leadRuleRead
	if err := json.Unmarshal(got.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	return rule
}

func approveLeadRule(t *testing.T, r *httpapitest.Reach, id int64) leadRuleRead {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
		fmt.Sprintf("%s/%d/approval", leadRulesAt, id), `{}`)
	if got.Code != http.StatusOK {
		t.Fatalf("approving rule %d answered %d: %s", id, got.Code, got.Body)
	}
	var rule leadRuleRead
	if err := json.Unmarshal(got.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	return rule
}

func leadRulesOf(t *testing.T, r *httpapitest.Reach) map[int64]leadRuleRead {
	t.Helper()
	var listed struct {
		Items []leadRuleRead `json:"items"`
	}
	httpapitest.Read(t, r, "internal-reader", leadRulesAt, &listed)
	out := map[int64]leadRuleRead{}
	for _, rule := range listed.Items {
		out[rule.ID] = rule
	}
	return out
}

func TestAStandingRuleDismissesNothingUntilSomebodyElseApprovesIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, "/v1/products/mine/leads/"+place+"/escalation", `{}`)
		rule := proposeLeadRule(t, r,
			`{"rule":"clang-tidy/leak","reason":"false_positive","reasoning":"every allocation here is pooled"}`)
		if rule.State != "proposed" || rule.Covering != 1 {
			t.Fatalf("the rule proposed is %+v", rule)
		}
		if got := leadsOf(t, r, "internal-reader", ""); len(got.Items) != 1 || got.Ruled != 0 {
			t.Fatalf("a rule nobody approved took the lead out of the queue: %+v", got)
		}
		approval := fmt.Sprintf("%s/%d/approval", leadRulesAt, rule.ID)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reviewer", http.MethodPost, approval, `{}`),
			http.StatusForbidden)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, approval, `{}`),
			http.StatusForbidden)
		approved := approveLeadRule(t, r, rule.ID)
		if approved.State != "in-force" || approved.Approved == nil || *approved.Approved != 1 || approved.Covering != 1 {
			t.Fatalf("the rule approved is %+v; want in force, approved covering the one lead", approved)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost, approval, `{}`),
			http.StatusConflict)
		got := leadsOf(t, r, "internal-reader", "")
		if len(got.Items) != 0 || got.Ruled != 1 || got.States["dismissed"] != 1 {
			t.Fatalf("the queue is %+v; want the lead left out and counted as ruled", got)
		}
		if got := leadState(t, r, place); got != "dismissed" {
			t.Errorf("the lead's evidence says %q; want dismissed", got)
		}
	})
}

func TestTheAuthorOfAStandingRuleCannotApproveIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		got := httpapitest.AsPerson(t, r, "internal-lead", http.MethodPost, leadRulesAt,
			`{"prefix":"tests","reason":"used_in_tests","reasoning":"the tests do not ship"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("proposing answered %d: %s", got.Code, got.Body)
		}
		var rule leadRuleRead
		if err := json.Unmarshal(got.Body.Bytes(), &rule); err != nil {
			t.Fatal(err)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-lead", http.MethodPost,
			fmt.Sprintf("%s/%d/approval", leadRulesAt, rule.ID), `{}`), http.StatusConflict)
		if listed := leadRulesOf(t, r)[rule.ID]; listed.State != "proposed" {
			t.Errorf("the rule is %+v after its author approved it; want it proposed still", listed)
		}
	})
}

func TestAStandingRuleCoversTheLeadsOfItsRuleUnderItsPath(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		const why = `"reason":"wont_fix","reasoning":"vendored"`
		want := map[int64]int{}
		for body, covering := range map[string]int{
			`{"rule":"clang-tidy/leak",` + why + `}`:                    1,
			`{"rule":"Clang-Tidy/leak",` + why + `}`:                    1,
			`{"rule":"clang-tidy/overflow","prefix":"src",` + why + `}`: 0,
			`{"prefix":"src",` + why + `}`:                              1,
			`{"prefix":"/src/a.c",` + why + `}`:                         1,
			`{"prefix":"sr",` + why + `}`:                               0,
			`{"rule":"clang-tidy/leak","prefix":"src",` + why + `}`:     1,
			`{"rule":"clang-tidy/leak","prefix":"src/b",` + why + `}`:   0,
		} {
			want[proposeLeadRule(t, r, body).ID] = covering
		}
		listed := leadRulesOf(t, r)
		for id, covering := range want {
			if got := listed[id]; got.Covering != covering {
				t.Errorf("rule %+v covers %d; want %d", got, got.Covering, covering)
			}
		}
	})
}

func TestAStandingRuleThatNamesNothingIsRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, body := range []string{
			`{"reason":"false_positive","reasoning":"everything"}`,
			`{"prefix":"/","reason":"false_positive","reasoning":"everything"}`,
			`{"rule":"clang-tidy/leak","prefix":"../etc","reason":"false_positive","reasoning":"outside"}`,
			`{"rule":"clang-tidy/leak","reason":"not_a_reason","reasoning":"why"}`,
			`{"rule":"clang-tidy/leak","reason":"false_positive","reasoning":"<b>raw</b>"}`,
		} {
			httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadRulesAt, body),
				http.StatusUnprocessableEntity)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodPost, leadRulesAt,
			`{"prefix":"tests","reason":"used_in_tests","reasoning":"the tests do not ship"}`), http.StatusForbidden)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, leadRulesAt, ""),
			http.StatusForbidden)
		if listed := leadRulesOf(t, r); len(listed) != 0 {
			t.Errorf("refused rules were recorded: %+v", listed)
		}
	})
}

// leadRunWithSecondLeak is the seeded run reporting a second leak, in
// another file.
func leadRunWithSecondLeak() string {
	return strings.Replace(httpapitest.LeadRunAt(12), `"results":[`,
		`"results":[{"ruleId":"leak","message":{"text":"q is leaked"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/c.c","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":4}}}]},`, 1)
}

func TestAStandingRuleThatOutgrowsItsApprovalAsksForItAgain(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if _, _, err := setting.NewStore(r.DB.DB).Change(t.Context(), setting.LeadRuleGrowth, "1"); err != nil {
			t.Fatal(err)
		}
		rule := proposeLeadRule(t, r, `{"rule":"clang-tidy/leak","prefix":"src","reason":"mitigated","reasoning":"sandboxed"}`)
		path := proposeLeadRule(t, r, `{"prefix":"src","reason":"mitigated","reasoning":"sandboxed"}`)
		approveLeadRule(t, r, rule.ID)
		approveLeadRule(t, r, path.ID)
		// Approved over nothing, the rule is measured as though it was shown
		// one lead.
		httpapitest.SeededLead(t, r)
		if got := leadRulesOf(t, r)[rule.ID]; got.State != "in-force" || got.Covering != 1 {
			t.Fatalf("the rule is %+v; want in force over its first lead", got)
		}
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), leadRunWithSecondLeak())
		if got := leadRulesOf(t, r)[rule.ID]; got.State != "outgrown" || got.Covering != 2 {
			t.Fatalf("the rule is %+v; want outgrown over two leads", got)
		}
		// Code under a dismissed path grows, and its rule asks nothing.
		if got := leadRulesOf(t, r)[path.ID]; got.State != "in-force" || got.Covering != 2 {
			t.Errorf("the path's rule is %+v; want in force over both leads", got)
		}
		retirePath := fmt.Sprintf("%s/%d", leadRulesAt, path.ID)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, retirePath, ""); got.Code != http.StatusNoContent {
			t.Fatalf("retiring the path's rule answered %d: %s", got.Code, got.Body)
		}
		if got := leadsOf(t, r, "internal-reader", "?state=dismissed"); got.Ruled != 2 || len(got.Items) != 2 {
			t.Errorf("an outgrown rule dismisses %+v; want both leads still", got)
		}
		if again := approveLeadRule(t, r, rule.ID); again.State != "in-force" || *again.Approved != 2 {
			t.Errorf("approved again, the rule is %+v; want in force at two", again)
		}

		retire := fmt.Sprintf("%s/%d", leadRulesAt, rule.ID)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodDelete, retire, ""),
			http.StatusForbidden)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, retire, ""); got.Code != http.StatusNoContent {
			t.Fatalf("retiring the rule answered %d: %s", got.Code, got.Body)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, retire, ""),
			http.StatusNotFound)
		if got := leadRulesOf(t, r)[rule.ID]; got.State != "retired" {
			t.Errorf("the rule is %+v; want retired", got)
		}
		if got := leadsOf(t, r, "internal-reader", ""); got.Ruled != 0 || got.States["dismissed"] != 0 {
			t.Errorf("a retired rule still dismisses: %+v", got)
		}
	})
}

func TestAMemorySafetyRuleIsDismissedOnlyUnderAPath(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour),
			ratedRun(`"tags":["external/cwe/cwe-563"]`, `"tags":["external/cwe/cwe-787"]`))
		const why = `"reason":"mitigated","reasoning":"bounds checked by the caller"`
		for _, body := range []string{
			`{"rule":"clang-tidy/overflow",` + why + `}`,
			`{"rule":"clang-tidy/never-reported",` + why + `}`,
		} {
			httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadRulesAt, body),
				http.StatusUnprocessableEntity)
		}
		proposeLeadRule(t, r, `{"rule":"clang-tidy/overflow","prefix":"src/c.c",`+why+`}`)
		proposeLeadRule(t, r, `{"rule":"clang-tidy/never-reported","prefix":"src",`+why+`}`)
		// Dead code is a class a rule may dismiss across the product.
		proposeLeadRule(t, r, `{"rule":"clang-tidy/leak",`+why+`}`)
	})
}

func TestARuleTaggedWithAWeaknessByNameIsClassifiedByIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		// semgrep tags a rule with the weakness's number and its name.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(
			`"tags":["CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"]`, ``))
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadRulesAt,
			`{"rule":"clang-tidy/leak","reason":"false_positive","reasoning":"sized by the caller"}`),
			http.StatusUnprocessableEntity)
	})
}

func TestARuleFoundToFindMemoryFlawsAfterItWasProposedIsNotApproved(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		rule := proposeLeadRule(t, r, `{"rule":"clang-tidy/leak","reason":"wont_fix","reasoning":"short-lived tool"}`)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour),
			ratedRun(`"tags":["external/cwe/cwe-416"]`, ``))
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("%s/%d/approval", leadRulesAt, rule.ID), `{}`), http.StatusUnprocessableEntity)
		if got := leadRulesOf(t, r)[rule.ID]; got.State != "needs-path" || got.Approved != nil {
			t.Errorf("the rule is %+v; want it unapproved, needing a path", got)
		}
	})
}

func TestAnInjectionRuleIsDismissedOnlyUnderAPath(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(`"tags":["external/cwe/cwe-89"]`, ``))
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadRulesAt,
			`{"rule":"clang-tidy/leak","reason":"false_positive","reasoning":"parameterized"}`), http.StatusUnprocessableEntity)
	})
}

func TestAWholeRuleDismissalStopsWhereItsRuleIsFoundToFindMemoryFlaws(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		rule := proposeLeadRule(t, r, `{"rule":"clang-tidy/leak","reason":"wont_fix","reasoning":"short-lived tool"}`)
		approveLeadRule(t, r, rule.ID)
		path := proposeLeadRule(t, r, `{"rule":"clang-tidy/leak","prefix":"src/d.c","reason":"wont_fix","reasoning":"pooled"}`)
		approveLeadRule(t, r, path.ID)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(`"tags":["external/cwe/cwe-416"]`, ``))
		listed := leadRulesOf(t, r)
		if got := listed[rule.ID]; got.State != "needs-path" {
			t.Fatalf("the rule is %+v; want it to need a path", got)
		}
		if got := listed[path.ID]; got.State != "in-force" {
			t.Errorf("the rule naming a path is %+v; want it in force", got)
		}
		// The leak the path names stays dismissed, and the one it does not
		// comes back.
		got := leadsOf(t, r, "internal-reader", "?state=dismissed")
		if len(got.Items) != 1 || got.Items[0].Path != "src/d.c" || got.Ruled != 1 {
			t.Errorf("the dismissed leads are %+v; want the one under the path alone", got)
		}
	})
}

func TestAWholeRuleDismissalStopsWhereItsRuleIsFoundToFindInjection(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		rule := proposeLeadRule(t, r, `{"rule":"clang-tidy/leak","reason":"wont_fix","reasoning":"short-lived tool"}`)
		approveLeadRule(t, r, rule.ID)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(`"tags":["external/cwe/cwe-77"]`, ``))
		if got := leadRulesOf(t, r)[rule.ID]; got.State != "needs-path" {
			t.Errorf("the rule is %+v; want it to need a path once its rule finds injection", got)
		}
		if got := leadsOf(t, r, "internal-reader", "?state=dismissed"); len(got.Items) != 0 || got.Ruled != 0 {
			t.Errorf("the dismissed leads are %+v; want none once the rule finds injection", got)
		}
	})
}

func TestARuleItsToolTagsWithNoWeaknessIsRatedByTheTableHeldForIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// clang names no weakness for unix.Malloc; the table holds that it
		// reports uses after free.
		httpapitest.SeededLead(t, r)
		doc := strings.ReplaceAll(httpapitest.LeadRunAt(12), `"leak"`, `"unix.Malloc"`)
		doc = strings.Replace(doc, `"name":"clang-tidy"`, `"name":"clang"`, 1)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), doc)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadRulesAt,
			`{"rule":"clang/unix.Malloc","reason":"false_positive","reasoning":"every allocation is pooled"}`),
			http.StatusUnprocessableEntity)
	})
}
