// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

const suppressionRulesAt = "/v1/products/mine/suppression-rules"

// suppressionRuleRead is a suppression rule as somebody reads it.
type suppressionRuleRead struct {
	ID       int64  `json:"id"`
	Rule     string `json:"rule"`
	Prefix   string `json:"prefix"`
	Approved *int   `json:"approved_covering"`
	Covering int    `json:"covering"`
	State    string `json:"state"`
}

func proposeSuppressionRule(t *testing.T, r *httpapitest.Reach, body string) suppressionRuleRead {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, suppressionRulesAt, body)
	if got.Code != http.StatusCreated {
		t.Fatalf("proposing %s answered %d: %s", body, got.Code, got.Body)
	}
	var rule suppressionRuleRead
	if err := json.Unmarshal(got.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	return rule
}

func approveSuppressionRule(t *testing.T, r *httpapitest.Reach, id int64) suppressionRuleRead {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
		fmt.Sprintf("%s/%d/approval", suppressionRulesAt, id), `{}`)
	if got.Code != http.StatusOK {
		t.Fatalf("approving rule %d answered %d: %s", id, got.Code, got.Body)
	}
	var rule suppressionRuleRead
	if err := json.Unmarshal(got.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	return rule
}

func suppressionRulesOf(t *testing.T, r *httpapitest.Reach) map[int64]suppressionRuleRead {
	t.Helper()
	var listed struct {
		Items []suppressionRuleRead `json:"items"`
	}
	httpapitest.Read(t, r, "internal-reader", suppressionRulesAt, &listed)
	out := map[int64]suppressionRuleRead{}
	for _, rule := range listed.Items {
		out[rule.ID] = rule
	}
	return out
}

func TestAStandingRuleDismissesNothingUntilSomebodyElseApprovesIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		rule := proposeSuppressionRule(t, r,
			`{"rule":"clang-tidy/leak","reason":"false_positive","reasoning":"every allocation here is pooled"}`)
		if rule.State != "proposed" || rule.Covering != 1 {
			t.Fatalf("the rule proposed is %+v", rule)
		}
		if got := codeFindingsOf(t, r, "internal-reader", ""); len(got.Items) != 1 || got.Ruled != 0 {
			t.Fatalf("a rule nobody approved took the code finding out of the queue: %+v", got)
		}
		approval := fmt.Sprintf("%s/%d/approval", suppressionRulesAt, rule.ID)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reviewer", http.MethodPost, approval, `{}`),
			http.StatusForbidden)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, approval, `{}`),
			http.StatusForbidden)
		approved := approveSuppressionRule(t, r, rule.ID)
		if approved.State != "in-force" || approved.Approved == nil || *approved.Approved != 1 || approved.Covering != 1 {
			t.Fatalf("the rule approved is %+v; want in force, approved covering the one code finding", approved)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost, approval, `{}`),
			http.StatusConflict)
		got := codeFindingsOf(t, r, "internal-reader", "")
		if len(got.Items) != 0 || got.Ruled != 1 || got.States["dismissed"] != 1 {
			t.Fatalf("the queue is %+v; want the code finding left out and counted as ruled", got)
		}
		if got := codeFindingState(t, r, occurrence); got != "dismissed" {
			t.Errorf("the code finding's evidence says %q; want dismissed", got)
		}
	})
}

func TestTheAuthorOfAStandingRuleCannotApproveIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		got := httpapitest.AsPerson(t, r, "internal-code-finding", http.MethodPost, suppressionRulesAt,
			`{"prefix":"tests","reason":"used_in_tests","reasoning":"the tests do not ship"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("proposing answered %d: %s", got.Code, got.Body)
		}
		var rule suppressionRuleRead
		if err := json.Unmarshal(got.Body.Bytes(), &rule); err != nil {
			t.Fatal(err)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-code-finding", http.MethodPost,
			fmt.Sprintf("%s/%d/approval", suppressionRulesAt, rule.ID), `{}`), http.StatusConflict)
		if listed := suppressionRulesOf(t, r)[rule.ID]; listed.State != "proposed" {
			t.Errorf("the rule is %+v after its author approved it; want it proposed still", listed)
		}
	})
}

func TestAStandingRuleCoversTheCodeFindingsOfItsRuleUnderItsPath(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
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
			want[proposeSuppressionRule(t, r, body).ID] = covering
		}
		listed := suppressionRulesOf(t, r)
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
			httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, suppressionRulesAt, body),
				http.StatusUnprocessableEntity)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodPost, suppressionRulesAt,
			`{"prefix":"tests","reason":"used_in_tests","reasoning":"the tests do not ship"}`), http.StatusForbidden)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, suppressionRulesAt, ""),
			http.StatusForbidden)
		if listed := suppressionRulesOf(t, r); len(listed) != 0 {
			t.Errorf("refused rules were recorded: %+v", listed)
		}
	})
}

// codeFindingRunWithSecondLeak is the seeded run reporting a second leak, in
// another file.
func codeFindingRunWithSecondLeak() string {
	return strings.Replace(httpapitest.CodeFindingRunAt(12), `"results":[`,
		`"results":[{"ruleId":"leak","message":{"text":"q is leaked"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/c.c","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":4}}}]},`, 1)
}

// outgrownTold sweeps, and is how many outgrown rules a person holds.
func outgrownTold(t *testing.T, r *httpapitest.Reach, who string) int {
	t.Helper()
	return ruleNoticesTold(t, r, who, notify.SuppressionRuleOutgrown)
}

// ruleNoticesTold sweeps, and is how many notices of one kind a person holds.
func ruleNoticesTold(t *testing.T, r *httpapitest.Reach, who string, kind notify.Kind) int {
	t.Helper()
	if _, _, err := notify.NewWatch(r.DB.DB, slog.New(slog.NewTextHandler(io.Discard, nil))).Once(t.Context()); err != nil {
		t.Fatal(err)
	}
	var theirs struct {
		Items []struct {
			Kind string `json:"kind"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, who, "/v1/notifications", &theirs)
	n := 0
	for _, item := range theirs.Items {
		if item.Kind == string(kind) {
			n++
		}
	}
	return n
}

func TestAStandingRuleThatOutgrowsItsApprovalAsksForItAgain(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if _, _, err := setting.NewStore(r.DB.DB).Change(t.Context(), setting.SuppressionRuleGrowth, "1"); err != nil {
			t.Fatal(err)
		}
		rule := proposeSuppressionRule(t, r, `{"rule":"clang-tidy/leak","prefix":"src","reason":"mitigated","reasoning":"sandboxed"}`)
		path := proposeSuppressionRule(t, r, `{"prefix":"src","reason":"mitigated","reasoning":"sandboxed"}`)
		approveSuppressionRule(t, r, rule.ID)
		approveSuppressionRule(t, r, path.ID)
		// Approved over nothing, the rule is measured as though it was shown
		// one code finding.
		httpapitest.SeededCodeFinding(t, r)
		if got := suppressionRulesOf(t, r)[rule.ID]; got.State != "in-force" || got.Covering != 1 {
			t.Fatalf("the rule is %+v; want in force over its first code finding", got)
		}
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), codeFindingRunWithSecondLeak())
		if got := suppressionRulesOf(t, r)[rule.ID]; got.State != "outgrown" || got.Covering != 2 {
			t.Fatalf("the rule is %+v; want outgrown over two code findings", got)
		}
		// Code under a dismissed path grows, and its rule asks nothing.
		if got := suppressionRulesOf(t, r)[path.ID]; got.State != "in-force" || got.Covering != 2 {
			t.Errorf("the path's rule is %+v; want in force over both code findings", got)
		}
		retirePath := fmt.Sprintf("%s/%d", suppressionRulesAt, path.ID)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, retirePath, ""); got.Code != http.StatusNoContent {
			t.Fatalf("retiring the path's rule answered %d: %s", got.Code, got.Body)
		}
		if got := codeFindingsOf(t, r, "internal-reader", "?state=dismissed"); got.Ruled != 2 || len(got.Items) != 2 {
			t.Errorf("an outgrown rule dismisses %+v; want both code findings still", got)
		}
		// Whoever may approve it again is told, and its proposer is not.
		if n := outgrownTold(t, r, "internal-reviewer"); n != 1 {
			t.Errorf("an internal approver holds %d outgrown rules; want 1", n)
		}
		if n := outgrownTold(t, r, "internal-triager"); n != 0 {
			t.Errorf("the rule's proposer holds %d outgrown rules; want none", n)
		}
		if n := outgrownTold(t, r, "internal-reader"); n != 0 {
			t.Errorf("an internal reader who may not approve holds %d outgrown rules; want none", n)
		}
		if again := approveSuppressionRule(t, r, rule.ID); again.State != "in-force" || *again.Approved != 2 {
			t.Errorf("approved again, the rule is %+v; want in force at two", again)
		}
		if n := outgrownTold(t, r, "internal-reviewer"); n != 0 {
			t.Errorf("approved again, the rule is still told as outgrown %d times", n)
		}

		retire := fmt.Sprintf("%s/%d", suppressionRulesAt, rule.ID)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodDelete, retire, ""),
			http.StatusForbidden)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, retire, ""); got.Code != http.StatusNoContent {
			t.Fatalf("retiring the rule answered %d: %s", got.Code, got.Body)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, retire, ""),
			http.StatusNotFound)
		if got := suppressionRulesOf(t, r)[rule.ID]; got.State != "retired" {
			t.Errorf("the rule is %+v; want retired", got)
		}
		if got := codeFindingsOf(t, r, "internal-reader", ""); got.Ruled != 0 || got.States["dismissed"] != 0 {
			t.Errorf("a retired rule still dismisses: %+v", got)
		}
	})
}

func TestAMemorySafetyRuleIsDismissedOnlyUnderAPath(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour),
			ratedRun(`"tags":["external/cwe/cwe-563"]`, `"tags":["external/cwe/cwe-787"]`))
		const why = `"reason":"mitigated","reasoning":"bounds checked by the caller"`
		for _, body := range []string{
			`{"rule":"clang-tidy/overflow",` + why + `}`,
			`{"rule":"clang-tidy/never-reported",` + why + `}`,
		} {
			httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, suppressionRulesAt, body),
				http.StatusUnprocessableEntity)
		}
		proposeSuppressionRule(t, r, `{"rule":"clang-tidy/overflow","prefix":"src/c.c",`+why+`}`)
		proposeSuppressionRule(t, r, `{"rule":"clang-tidy/never-reported","prefix":"src",`+why+`}`)
		// Dead code is a class a rule may dismiss across the product.
		proposeSuppressionRule(t, r, `{"rule":"clang-tidy/leak",`+why+`}`)
	})
}

func TestARuleTaggedWithAWeaknessByNameIsClassifiedByIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		// semgrep tags a rule with the weakness's number and its name.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(
			`"tags":["CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')"]`, ``))
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, suppressionRulesAt,
			`{"rule":"clang-tidy/leak","reason":"false_positive","reasoning":"sized by the caller"}`),
			http.StatusUnprocessableEntity)
	})
}

func TestARuleFoundToFindMemoryFlawsAfterItWasProposedIsNotApproved(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		rule := proposeSuppressionRule(t, r, `{"rule":"clang-tidy/leak","reason":"wont_fix","reasoning":"short-lived tool"}`)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour),
			ratedRun(`"tags":["external/cwe/cwe-416"]`, ``))
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("%s/%d/approval", suppressionRulesAt, rule.ID), `{}`), http.StatusUnprocessableEntity)
		if got := suppressionRulesOf(t, r)[rule.ID]; got.State != "needs-path" || got.Approved != nil {
			t.Errorf("the rule is %+v; want it unapproved, needing a path", got)
		}
	})
}

func TestAnInjectionRuleIsDismissedOnlyUnderAPath(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(`"tags":["external/cwe/cwe-89"]`, ``))
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, suppressionRulesAt,
			`{"rule":"clang-tidy/leak","reason":"false_positive","reasoning":"parameterized"}`), http.StatusUnprocessableEntity)
	})
}

func TestAWholeRuleDismissalStopsWhereItsRuleIsFoundToFindMemoryFlaws(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		rule := proposeSuppressionRule(t, r, `{"rule":"clang-tidy/leak","reason":"wont_fix","reasoning":"short-lived tool"}`)
		approveSuppressionRule(t, r, rule.ID)
		path := proposeSuppressionRule(t, r, `{"rule":"clang-tidy/leak","prefix":"src/d.c","reason":"wont_fix","reasoning":"pooled"}`)
		approveSuppressionRule(t, r, path.ID)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(`"tags":["external/cwe/cwe-416"]`, ``))
		listed := suppressionRulesOf(t, r)
		if got := listed[rule.ID]; got.State != "needs-path" {
			t.Fatalf("the rule is %+v; want it to need a path", got)
		}
		if got := listed[path.ID]; got.State != "in-force" {
			t.Errorf("the rule naming a path is %+v; want it in force", got)
		}
		// The leak the path names stays dismissed, and the one it does not
		// comes back.
		got := codeFindingsOf(t, r, "internal-reader", "?state=dismissed")
		if len(got.Items) != 1 || got.Items[0].Path != "src/d.c" || got.Ruled != 1 {
			t.Errorf("the dismissed code findings are %+v; want the one under the path alone", got)
		}
	})
}

func TestAWholeRuleDismissalStopsWhereItsRuleIsFoundToFindInjection(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		rule := proposeSuppressionRule(t, r, `{"rule":"clang-tidy/leak","reason":"wont_fix","reasoning":"short-lived tool"}`)
		approveSuppressionRule(t, r, rule.ID)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), ratedRun(`"tags":["external/cwe/cwe-77"]`, ``))
		if got := suppressionRulesOf(t, r)[rule.ID]; got.State != "needs-path" {
			t.Errorf("the rule is %+v; want it to need a path once its rule finds injection", got)
		}
		if got := codeFindingsOf(t, r, "internal-reader", "?state=dismissed"); len(got.Items) != 0 || got.Ruled != 0 {
			t.Errorf("the dismissed code findings are %+v; want none once the rule finds injection", got)
		}
	})
}

func TestARuleItsToolTagsWithNoWeaknessIsRatedByTheTableHeldForIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// clang names no weakness for unix.Malloc; the table holds that it
		// reports uses after free.
		httpapitest.SeededCodeFinding(t, r)
		doc := strings.ReplaceAll(httpapitest.CodeFindingRunAt(12), `"leak"`, `"unix.Malloc"`)
		doc = strings.Replace(doc, `"name":"clang-tidy"`, `"name":"clang"`, 1)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), doc)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, suppressionRulesAt,
			`{"rule":"clang/unix.Malloc","reason":"false_positive","reasoning":"every allocation is pooled"}`),
			http.StatusUnprocessableEntity)
	})
}

// A suppression rule nobody approves dismisses nothing, so whoever may approve it
// is told once it has waited the period a decision waits, and never its
// proposer.
func TestAStandingRuleWaitingForApprovalIsToldToWhoeverMayApproveIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// The proposer may approve as well, so leaving them out is the
		// proposer rule and nothing else.
		ctx := t.Context()
		proposer, err := r.Rights.Ensure(ctx, "internal-triager", httpapitest.ShownAs("internal-triager"), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		mine, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Rights.GrantRole(ctx, proposer.ID, mine.ID, access.Approver); err != nil {
			t.Fatal(err)
		}
		rule := proposeSuppressionRule(t, r, `{"prefix":"tests","reason":"used_in_tests","reasoning":"the tests do not ship"}`)
		if n := ruleNoticesTold(t, r, "internal-reviewer", notify.SuppressionRuleWaiting); n != 0 {
			t.Fatalf("a rule proposed a moment ago was told as waiting %d times", n)
		}
		// One approved beside it waits for nobody.
		approveSuppressionRule(t, r, proposeSuppressionRule(t, r,
			`{"prefix":"examples","reason":"used_in_tests","reasoning":"the examples do not ship"}`).ID)
		if _, err := r.DB.DB.NewUpdate().Table("suppression_rule").
			Set(`"proposed_at" = ?`, time.Now().UTC().Add(-30*24*time.Hour)).
			Where(`1 = 1`).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if n := ruleNoticesTold(t, r, "internal-reviewer", notify.SuppressionRuleWaiting); n != 1 {
			t.Errorf("an internal approver holds %d waiting rules; want 1", n)
		}
		if n := ruleNoticesTold(t, r, "internal-triager", notify.SuppressionRuleWaiting); n != 0 {
			t.Errorf("the rule's proposer holds %d waiting rules; want none", n)
		}
		if n := ruleNoticesTold(t, r, "internal-reader", notify.SuppressionRuleWaiting); n != 0 {
			t.Errorf("an internal reader who may not approve holds %d waiting rules; want none", n)
		}
		approveSuppressionRule(t, r, rule.ID)
		if n := ruleNoticesTold(t, r, "internal-reviewer", notify.SuppressionRuleWaiting); n != 0 {
			t.Errorf("an approved rule is still told as waiting %d times", n)
		}
	})
}

func TestADecisionAboutACodeFindingOverridesTheStandingRuleDismissingIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		rule := proposeSuppressionRule(t, r,
			`{"rule":"clang-tidy/leak","reason":"false_positive","reasoning":"every allocation here is pooled"}`)
		approveSuppressionRule(t, r, rule.ID)
		if got := codeFindingState(t, r, occurrence); got != "dismissed" {
			t.Fatalf("a code finding under a rule in force is %q; want dismissed", got)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(codeFindingDecisionAt, occurrence),
			`{"outcome":"confirmed","reasoning":"this one is not pooled"}`); got.Code != http.StatusCreated {
			t.Fatalf("the confirmation answered %d: %s", got.Code, got.Body)
		}
		if got := codeFindingState(t, r, occurrence); got != "confirmed" {
			t.Errorf("a code finding confirmed under a rule dismissing it is %q; want confirmed", got)
		}
		if got := codeFindingsOf(t, r, "internal-reader", "?state=confirmed"); len(got.Items) != 1 || got.Items[0].Occurrence != occurrence {
			t.Errorf("the confirmed code findings are %+v; want the code finding the rule covers", got.Items)
		}
	})
}
