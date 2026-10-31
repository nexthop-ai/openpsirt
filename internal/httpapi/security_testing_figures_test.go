// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

const (
	judgeOf     = "/v1/products/mine/code-finding-time-to-judge"
	fixOf       = "/v1/products/mine/code-finding-time-to-fix"
	precisionOf = "/v1/products/mine/code-finding-precision"
	coverageOf  = "/v1/products/mine/analysis-coverage"
	releasesOf  = "/v1/products/mine/code-findings-by-release"
)

type waitRead struct {
	Tier   string  `json:"tier"`
	Count  int     `json:"count"`
	Median float64 `json:"median_days"`
	P90    float64 `json:"p90_days"`
	Worst  float64 `json:"worst_days"`
}

type waitsRead struct {
	All    waitRead   `json:"all"`
	ByTier []waitRead `json:"by_tier"`
}

func (w waitsRead) tier(name string) waitRead {
	for _, each := range w.ByTier {
		if each.Tier == name {
			return each
		}
	}
	return waitRead{Tier: "absent"}
}

type judgingRead struct {
	Judged  waitsRead `json:"judged"`
	Waiting []struct {
		Label   string         `json:"label"`
		Waiting int            `json:"waiting"`
		ByTier  map[string]int `json:"by_tier"`
	} `json:"waiting"`
	Oldest           string `json:"oldest"`
	NoLongerDetected int    `json:"no_longer_detected"`
}

type fixingRead struct {
	Fixed            waitsRead `json:"fixed"`
	Dismissed        int       `json:"dismissed"`
	NoLongerDetected waitsRead `json:"no_longer_detected"`
}

type answeredRead struct {
	Series      string   `json:"series"`
	Rule        string   `json:"rule"`
	Judged      int      `json:"judged"`
	Dismissed   int      `json:"dismissed"`
	NotSecurity int      `json:"not_security"`
	Ruled       int      `json:"ruled"`
	Confirmed   int      `json:"confirmed"`
	Fixed       int      `json:"fixed"`
	Unjudged    int      `json:"unjudged"`
	NoiseShare  *float64 `json:"noise_share"`
}

type precisionRead struct {
	BySeries []answeredRead `json:"by_series"`
	ByRule   []answeredRead `json:"by_rule"`
	Rules    []struct {
		Rule     string `json:"rule"`
		Prefix   string `json:"path"`
		State    string `json:"state"`
		Covering int    `json:"covering"`
	} `json:"suppression_rules"`
}

func (p precisionRead) series(name string) answeredRead {
	for _, each := range p.BySeries {
		if each.Series == name {
			return each
		}
	}
	return answeredRead{Series: "absent"}
}

// atOf is the address of one of the hub's code findings on its build, by its
// series.
func atOf(t *testing.T, r *httpapitest.Reach, series, state string) string {
	t.Helper()
	query := "?series=" + series
	if state != "" {
		query += "&state=" + state
	}
	items := hubQueueOf(t, r, "code-finding-handler", query).Items
	if len(items) != 1 {
		t.Fatalf("%s lists %d code findings in %s; want one", series, len(items), query)
	}
	return hubBuild + "/code-findings/" + items[0].Occurrence
}

// decided records a decision about a code finding, and has the reviewer agree
// to it where it waits on a second person.
func decided(t *testing.T, r *httpapitest.Reach, at, body string, agreed bool) int64 {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, at+"/decision", body)
	var made struct {
		DecisionID int64 `json:"decision_id"`
	}
	if got.Code != http.StatusCreated || json.Unmarshal(got.Body.Bytes(), &made) != nil {
		t.Fatalf("deciding %s answered %d: %s", at, got.Code, got.Body)
	}
	if agreed {
		r.AgreedBy(t, "security-testing-reviewer", made.DecisionID)
	}
	return made.DecisionID
}

const dismissal = `{"outcome":"dismissed","reason":"false_positive","reasoning":"checked a line above"}`

// The queue waits by age, and a first decision is timed from opening: a
// dismissal counts as a judgment, and no longer detected is apart.
func TestTimeToJudgeIsFromOpeningToTheFirstProposal(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		var before judgingRead
		httpapitest.Read(t, r, "security-testing-reader", judgeOf+"?weeks=2", &before)
		// semgrep's opened ten days ago; CodeQL's within the hour.
		if len(before.Waiting) != 4 || before.Waiting[0].Waiting != 1 || before.Waiting[0].ByTier["memory-safety"] != 1 ||
			before.Waiting[1].Waiting != 1 || before.Waiting[1].ByTier["other"] != 1 ||
			before.Waiting[2].Waiting != 0 || before.Waiting[3].Waiting != 0 {
			t.Errorf("the queue ages as %+v; want CodeQL's under a week and semgrep's at one to four weeks", before.Waiting)
		}
		if want := time.Now().UTC().Add(-10 * 24 * time.Hour).Format(time.DateOnly); before.Oldest != want {
			t.Errorf("the oldest waiting opened %q; want %s", before.Oldest, want)
		}
		if before.Judged.All.Count != 0 || before.NoLongerDetected != 1 {
			t.Errorf("before any decision %+v; want nothing judged and cppcheck's no longer detected", before)
		}

		decided(t, r, atOf(t, r, "semgrep/default", ""), dismissal, true)
		confirmed := decided(t, r, atOf(t, r, "codeql/default", ""), `{"outcome":"confirmed","reasoning":"the length is the caller's"}`, false)
		var after judgingRead
		httpapitest.Read(t, r, "security-testing-reader", judgeOf+"?weeks=2", &after)
		all := after.Judged.All
		if all.Count != 2 || all.Median != 0 || all.P90 != 10 || all.Worst != 10 {
			t.Errorf("the judged are %+v; want two, a median of none and a ninetieth of ten days", all)
		}
		if got := after.Judged.tier("memory-safety"); got.Count != 1 || got.Worst != 0 {
			t.Errorf("memory safety is %+v; want CodeQL's judged at once", got)
		}
		if got := after.Judged.tier("other"); got.Count != 1 || got.Median != 10 {
			t.Errorf("other is %+v; want semgrep's dismissal after ten days", got)
		}
		for _, aged := range after.Waiting {
			if aged.Waiting != 0 {
				t.Errorf("%s still waits %d; want the queue empty", aged.Label, aged.Waiting)
			}
		}
		if after.Oldest != "" {
			t.Errorf("an empty queue's oldest is %q", after.Oldest)
		}
		// A first proposal before the window is not in it.
		var earlier judgingRead
		httpapitest.Read(t, r, "security-testing-reader", judgeOf+"?weeks=1&series=semgrep/default", &earlier)
		if earlier.Judged.All.Count != 1 {
			t.Errorf("semgrep alone is %+v; want its one dismissal", earlier.Judged)
		}
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"decision_occurrence"`).
			Set(`"proposed_at" = ?`, time.Now().UTC().Add(-9*24*time.Hour)).
			Where(`"proposed_at" IS NOT NULL`).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		httpapitest.Read(t, r, "security-testing-reader", judgeOf+"?weeks=1", &earlier)
		if earlier.Judged.All.Count != 0 {
			t.Errorf("decisions proposed nine days ago are %+v in the last week", earlier.Judged)
		}
		// A second decision this week about a code finding first judged nine
		// days ago is no first judgment.
		if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodDelete,
			fmt.Sprintf("/v1/decisions/%d", confirmed), ""); w.Code >= 300 {
			t.Fatalf("withdrawing the confirmation answered %d: %s", w.Code, w.Body)
		}
		decided(t, r, atOf(t, r, "codeql/default", ""), dismissal, false)
		httpapitest.Read(t, r, "security-testing-reader", judgeOf+"?weeks=1", &earlier)
		if earlier.Judged.All.Count != 0 {
			t.Errorf("a second decision this week is %+v; want no first judgment in the week", earlier.Judged)
		}
	})
}

// A fix is timed from opening to the closing; a dismissed code finding closed
// as fixed is left out and counted, and no longer detected is timed apart.
func TestTimeToFixLeavesOutDismissalsAndTimesAbsenceApart(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		var got fixingRead
		httpapitest.Read(t, r, "security-testing-reader", fixOf+"?weeks=2", &got)
		if all := got.Fixed.All; all.Count != 1 || all.Median != 10 || got.Fixed.tier("other").Count != 1 {
			t.Errorf("the fixed are %+v; want clang-tidy's leak after ten days", got.Fixed)
		}
		if got.Dismissed != 0 {
			t.Errorf("%d dismissed; want none", got.Dismissed)
		}
		if absent := got.NoLongerDetected.All; absent.Count != 1 || absent.Median != 10 {
			t.Errorf("no longer detected is %+v; want cppcheck's, unseen ten days after it opened", absent)
		}

		cppcheck := atOf(t, r, "cppcheck/default", "no-longer-detected")
		decided(t, r, cppcheck, dismissal, true)
		body := httpapitest.FixedBody(t, r, cppcheck, "the parser was rewritten")
		if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, cppcheck+"/fixed", body); w.Code != http.StatusOK {
			t.Fatalf("closing cppcheck's as fixed answered %d: %s", w.Code, w.Body.String())
		}
		httpapitest.Read(t, r, "security-testing-reader", fixOf+"?weeks=2", &got)
		if got.Fixed.All.Count != 1 || got.Dismissed != 1 || got.NoLongerDetected.All.Count != 0 {
			t.Errorf("after the dismissed one is fixed: %+v; want the leak alone fixed and one dismissed left out", got)
		}
		// A closing before the window is not in it.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_at" = ?`, time.Now().UTC().Add(-8*24*time.Hour)).
			Where(`"closed_at" IS NOT NULL`).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		httpapitest.Read(t, r, "security-testing-reader", fixOf+"?weeks=1", &got)
		if got.Fixed.All.Count != 0 || got.Dismissed != 0 {
			t.Errorf("closings eight days ago are %+v in the last week", got)
		}
	})
}

// stable is a second branch of the seeded product holding the hub's
// inventory.
var stable = httpapitest.Build{Product: "mine", BranchOrTag: "stable", Variant: "broadcom"}

// backported ships the hub's inventory on stable and applies clang-tidy's run
// finding the leak there, so the leak trendSeeded fixed on master is open on
// stable. It returns the leak's address on stable.
func backported(t *testing.T, r *httpapitest.Reach) string {
	t.Helper()
	names := catalog.NewStore(r.DB.DB)
	mine, err := names.ProductByName(t.Context(), "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.DeclareBranchOrTag(t.Context(), mine.ID, stable.BranchOrTag, catalog.Branch, nil); err != nil {
		t.Fatal(err)
	}
	_, scan := r.Shipped(t, stable, "hub-stable", graph.Snapshot{
		Root:       httpapitest.HubRoot,
		Components: []graph.Described{httpapitest.HubLib, httpapitest.HubTools, httpapitest.HubZlib},
		Dependencies: []graph.Dependency{
			{Parent: httpapitest.HubRoot, Child: httpapitest.HubLib},
			{Parent: httpapitest.HubRoot, Child: httpapitest.HubTools},
			{Parent: httpapitest.HubLib, Child: httpapitest.HubZlib},
		},
	})
	if err := ingest.NewStore(r.DB.DB).Made(t.Context(), scan, 4, 4, httpapitest.HubRoot.Name); err != nil {
		t.Fatal(err)
	}
	httpapitest.ApplyRunAt(t, r, stable, "clang-tidy/default", time.Now().UTC().Add(-time.Hour),
		httpapitest.CodeFindingRun(true))
	var items struct {
		Items []struct {
			Occurrence string `json:"occurrence"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, "code-finding-handler",
		"/v1/products/mine/code-findings?branch_or_tag=stable&variant=broadcom&series=clang-tidy/default", &items)
	if len(items.Items) != 1 {
		t.Fatalf("stable's queue is %+v; want the leak", items)
	}
	return "/v1/products/mine/branches-and-tags/stable/variants/broadcom/code-findings/" + items.Items[0].Occurrence
}

// A code finding is fixed once no build in the scope holds it open: the leak
// fixed on master and open on stable is neither timed as fixed nor counted
// fixed in precision until stable's closes too.
func TestAFixCountsOnceNoBuildHoldsItOpen(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		leak := backported(t, r)

		var fixing fixingRead
		httpapitest.Read(t, r, "security-testing-reader", fixOf+"?weeks=2", &fixing)
		if fixing.Fixed.All.Count != 0 {
			t.Errorf("the fixed are %+v; want none while stable holds the leak open", fixing.Fixed)
		}
		var precise precisionRead
		httpapitest.Read(t, r, "security-testing-reader", precisionOf, &precise)
		if got := precise.series("clang-tidy/default"); got.Fixed != 0 || got.Unjudged != 1 {
			t.Errorf("clang-tidy is %+v; want the leak unjudged while stable holds it open", got)
		}

		httpapitest.ApplyRunAt(t, r, stable, "clang-tidy/default", time.Now().UTC().Add(-30*time.Minute),
			httpapitest.CodeFindingRun(false))
		body := httpapitest.FixedBody(t, r, leak, "backported the fix")
		if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, leak+"/fixed", body); w.Code != http.StatusOK {
			t.Fatalf("closing stable's leak as fixed answered %d: %s", w.Code, w.Body.String())
		}
		httpapitest.Read(t, r, "security-testing-reader", fixOf+"?weeks=2", &fixing)
		if all := fixing.Fixed.All; all.Count != 1 || all.Median != 10 {
			t.Errorf("the fixed are %+v; want the leak once, ten days from master's opening", fixing.Fixed)
		}
		httpapitest.Read(t, r, "security-testing-reader", precisionOf, &precise)
		if got := precise.series("clang-tidy/default"); got.Fixed != 1 || got.Unjudged != 0 {
			t.Errorf("clang-tidy is %+v; want the leak fixed once", got)
		}
	})
}

// A code finding a suppression rule dismisses, with no decision standing, is
// left out of fixed and counted dismissed.
func TestTimeToFixLeavesOutWhatASuppressionRuleDismisses(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		cppcheck := atOf(t, r, "cppcheck/default", "no-longer-detected")
		rule := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, "/v1/products/mine/suppression-rules",
			`{"prefix":"inflate.cpp","reason":"false_positive","reasoning":"vendored and audited upstream"}`)
		var proposed struct {
			ID int64 `json:"id"`
		}
		if rule.Code != http.StatusCreated || json.Unmarshal(rule.Body.Bytes(), &proposed) != nil {
			t.Fatalf("proposing the rule answered %d: %s", rule.Code, rule.Body)
		}
		if w := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/products/mine/suppression-rules/%d/approval", proposed.ID), `{}`); w.Code != http.StatusOK {
			t.Fatalf("approving the rule answered %d: %s", w.Code, w.Body)
		}
		body := httpapitest.FixedBody(t, r, cppcheck, "the parser was rewritten")
		if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, cppcheck+"/fixed", body); w.Code != http.StatusOK {
			t.Fatalf("closing cppcheck's as fixed answered %d: %s", w.Code, w.Body.String())
		}
		var got fixingRead
		httpapitest.Read(t, r, "security-testing-reader", fixOf+"?weeks=2", &got)
		if got.Fixed.All.Count != 1 || got.Dismissed != 1 {
			t.Errorf("after the ruled one is fixed: %+v; want the leak alone fixed and one dismissed left out", got)
		}
	})
}

// Each code finding is counted once, at the first answer that holds, and the
// noise share is of those judged.
func TestPrecisionCountsEachCodeFindingAtItsFirstAnswer(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		var got precisionRead
		httpapitest.Read(t, r, "security-testing-reader", precisionOf, &got)
		if leak := got.series("clang-tidy/default"); leak.Fixed != 1 || leak.Judged != 1 || leak.NoiseShare == nil || *leak.NoiseShare != 0 {
			t.Errorf("clang-tidy is %+v; want its leak fixed, judged and no noise", leak)
		}
		for _, name := range []string{"cppcheck/default", "semgrep/default", "codeql/default"} {
			if each := got.series(name); each.Unjudged != 1 || each.Judged != 0 || each.NoiseShare != nil {
				t.Errorf("%s is %+v; want one unjudged and no share", name, each)
			}
		}
		if len(got.ByRule) != 1 || got.ByRule[0].Rule != "clang-tidy/leak" {
			t.Errorf("the rules judged are %+v; want the leak alone", got.ByRule)
		}

		decided(t, r, atOf(t, r, "semgrep/default", ""), dismissal, true)
		decided(t, r, atOf(t, r, "codeql/default", ""),
			`{"outcome":"not-security","reasoning":"only the test harness reaches it"}`, true)
		rule := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, "/v1/products/mine/suppression-rules",
			`{"prefix":"inflate.cpp","reason":"false_positive","reasoning":"vendored and audited upstream"}`)
		var proposed struct {
			ID int64 `json:"id"`
		}
		if rule.Code != http.StatusCreated || json.Unmarshal(rule.Body.Bytes(), &proposed) != nil {
			t.Fatalf("proposing the rule answered %d: %s", rule.Code, rule.Body)
		}
		if w := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/products/mine/suppression-rules/%d/approval", proposed.ID), `{}`); w.Code != http.StatusOK {
			t.Fatalf("approving the rule answered %d: %s", w.Code, w.Body)
		}

		httpapitest.Read(t, r, "security-testing-reader", precisionOf, &got)
		for name, want := range map[string]answeredRead{
			"semgrep/default":  {Dismissed: 1, Judged: 1},
			"codeql/default":   {NotSecurity: 1, Judged: 1},
			"cppcheck/default": {Ruled: 1, Judged: 1},
		} {
			each := got.series(name)
			if each.Dismissed != want.Dismissed || each.NotSecurity != want.NotSecurity || each.Ruled != want.Ruled ||
				each.Judged != 1 || each.Unjudged != 0 || each.NoiseShare == nil || *each.NoiseShare != 1 {
				t.Errorf("%s is %+v; want %+v and all of it noise", name, each, want)
			}
		}
		if len(got.ByRule) != 4 || got.ByRule[3].Rule != "clang-tidy/leak" {
			t.Errorf("the rules are %+v; want the leak, no noise, last", got.ByRule)
		}
		if len(got.Rules) != 1 || got.Rules[0].Prefix != "inflate.cpp" || got.Rules[0].State != "in-force" || got.Rules[0].Covering != 1 {
			t.Errorf("the suppression rules are %+v; want inflate.cpp in force covering cppcheck's", got.Rules)
		}

		decided(t, r, atOf(t, r, "cppcheck/default", "dismissed"), `{"outcome":"confirmed","reasoning":"real after all"}`, false)
		httpapitest.Read(t, r, "security-testing-reader", precisionOf, &got)
		if each := got.series("cppcheck/default"); each.Confirmed != 1 || each.Ruled != 0 || *each.NoiseShare != 0 {
			t.Errorf("cppcheck confirmed under a rule is %+v; want the decision over the rule", each)
		}
	})
}

type coverageRead struct {
	Quiet int `json:"quiet"`
	Items []struct {
		Product           string   `json:"product"`
		BranchOrTag       string   `json:"branch_or_tag"`
		Series            string   `json:"series"`
		Quiet             bool     `json:"quiet"`
		PastEndOfLife     bool     `json:"past_end_of_life"`
		NotComparable     string   `json:"not_comparable"`
		UnitsExpected     *int     `json:"units_expected"`
		UnitsAnalyzed     *int     `json:"units_analyzed"`
		Comparable        string   `json:"last_comparable"`
		AppliedRuns       int      `json:"applied_runs"`
		NotComparableRuns int      `json:"not_comparable_runs"`
		FailedRuns        int      `json:"failed_runs"`
		Expected          *float64 `json:"expected_days"`
		Silent            *float64 `json:"silent_days"`
	} `json:"items"`
}

// Each series is quiet against its own interval: clang-tidy runs daily and
// has been silent four days, cppcheck quarterly and silent ninety.
func TestAnalysisCoverageJudgesEachSeriesAgainstItsOwnInterval(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		ctx := t.Context()
		day := 24 * time.Hour
		now := time.Now().UTC()
		arrivals := map[string][]time.Duration{
			"clang-tidy/default": {6 * day, 5 * day, 4 * day},
			"cppcheck/default":   {270 * day, 180 * day, 90 * day},
		}
		for name, ago := range arrivals {
			var ids []int64
			if err := r.DB.DB.NewSelect().TableExpr(`"series_run" AS "sr"`).
				Join(`JOIN "series" AS "se" ON "se"."id" = "sr"."series_id"`).
				ColumnExpr(`"sr"."id"`).Where(`"se"."name" = ?`, name).
				OrderExpr(`"sr"."built_at", "sr"."id"`).Scan(ctx, &ids); err != nil {
				t.Fatal(err)
			}
			if len(ids) != len(ago) {
				t.Fatalf("%s has %d runs; want %d", name, len(ids), len(ago))
			}
			for i, id := range ids {
				if _, err := r.DB.DB.NewUpdate().TableExpr(`"series_run"`).
					Set(`"received_at" = ?`, now.Add(-ago[i])).Where(`"id" = ?`, id).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
		// semgrep's short run never read.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"series_run"`).Set(`"status" = 'failed'`).
			Where(`"comparable" = FALSE AND "not_comparable" = 'units-short'`).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		read := func() map[string]int {
			var got coverageRead
			httpapitest.Read(t, r, "security-testing-reader", coverageOf+"?weeks=1", &got)
			at := map[string]int{}
			for i, each := range got.Items {
				at[each.Series] = i
			}
			if len(got.Items) != 4 {
				t.Fatalf("coverage lists %+v; want four series on the build", got.Items)
			}
			return at
		}
		var got coverageRead
		at := read()
		httpapitest.Read(t, r, "security-testing-reader", coverageOf+"?weeks=1", &got)
		daily, quarterly := got.Items[at["clang-tidy/default"]], got.Items[at["cppcheck/default"]]
		if !daily.Quiet || daily.Expected == nil || *daily.Expected != 1 || *daily.Silent != 4 || got.Quiet != 1 || at["clang-tidy/default"] != 0 {
			t.Errorf("clang-tidy is %+v (quiet %d); want quiet first, a day expected and four silent", daily, got.Quiet)
		}
		if quarterly.Quiet || quarterly.Expected == nil || *quarterly.Expected != 90 || *quarterly.Silent != 90 {
			t.Errorf("cppcheck is %+v; want ninety days expected and not quiet after ninety", quarterly)
		}
		if daily.AppliedRuns != 3 || daily.NotComparableRuns != 1 || quarterly.AppliedRuns != 0 || daily.Comparable == "" {
			t.Errorf("the week's runs are %+v and %+v; want clang-tidy's three, one at a new version, and none of cppcheck's", daily, quarterly)
		}
		semgrep, codeql := got.Items[at["semgrep/default"]], got.Items[at["codeql/default"]]
		if semgrep.FailedRuns != 1 || semgrep.Expected != nil || semgrep.Quiet {
			t.Errorf("semgrep is %+v; want its one failed run and no rhythm", semgrep)
		}
		if codeql.UnitsExpected == nil || *codeql.UnitsExpected != 1 || *codeql.UnitsAnalyzed != 1 || codeql.NotComparable != "" {
			t.Errorf("CodeQL is %+v; want one unit of one, comparable", codeql)
		}

		// Runs arriving on schedule whose absences prove nothing are as
		// quiet as runs that stopped: clang-tidy's newest two arrive daily,
		// both not comparable, and its newest comparable one is four days old.
		var tidy []int64
		if err := r.DB.DB.NewSelect().TableExpr(`"series_run" AS "sr"`).
			Join(`JOIN "series" AS "se" ON "se"."id" = "sr"."series_id"`).
			ColumnExpr(`"sr"."id"`).Where(`"se"."name" = 'clang-tidy/default'`).
			OrderExpr(`"sr"."built_at", "sr"."id"`).Scan(ctx, &tidy); err != nil {
			t.Fatal(err)
		}
		for i, id := range tidy {
			q := r.DB.DB.NewUpdate().TableExpr(`"series_run"`).
				Set(`"received_at" = ?`, now.Add(-time.Duration(4-i)*day)).Where(`"id" = ?`, id)
			if i == 0 {
				q = q.Set(`"comparable" = TRUE`).Set(`"not_comparable" = NULL`)
			} else {
				q = q.Set(`"comparable" = FALSE`).Set(`"not_comparable" = 'units-short'`)
			}
			if _, err := q.Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		at = read()
		httpapitest.Read(t, r, "security-testing-reader", coverageOf+"?weeks=1", &got)
		if daily = got.Items[at["clang-tidy/default"]]; !daily.Quiet || *daily.Silent != 4 || daily.NotComparable != "units-short" {
			t.Errorf("clang-tidy is %+v; want quiet four days after its newest comparable run, though a run arrived two days ago", daily)
		}

		// A release past its end of life is listed and never quiet.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"branch_or_tag"`).
			Set(`"eol_on" = ?`, now.Add(-30*day)).Where(`"name" = 'master'`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		httpapitest.Read(t, r, "security-testing-reader", coverageOf+"?weeks=1", &got)
		for _, each := range got.Items {
			if !each.PastEndOfLife || each.Quiet {
				t.Errorf("%s past end of life is %+v; want marked and not quiet", each.Series, each)
			}
		}
		if got.Quiet != 0 {
			t.Errorf("%d quiet past end of life", got.Quiet)
		}

		// A build retired at any level is left out: its variant, its
		// branch, or its product.
		for _, retired := range []struct{ table, name string }{
			{`"variant"`, "broadcom"}, {`"branch_or_tag"`, "master"}, {`"product"`, "mine"},
		} {
			retire := func(when *time.Time) {
				if _, err := r.DB.DB.NewUpdate().TableExpr(retired.table).
					Set(`"retired_at" = ?`, when).Where(`"name" = ?`, retired.name).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
			retire(&now)
			httpapitest.Read(t, r, "security-testing-reader", coverageOf+"?weeks=1", &got)
			if len(got.Items) != 0 {
				t.Errorf("with %s %s retired coverage lists %+v; want nothing", retired.table, retired.name, got.Items)
			}
			retire(nil)
		}
	})
}

// tagged ships a tag of the seeded product with nothing but its root,
// released on the day given, and applies a run of CodeQL to it.
func tagged(t *testing.T, r *httpapitest.Reach, name string, released time.Time, doc string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	mine, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	tag, err := names.DeclareBranchOrTag(ctx, mine.ID, name, catalog.Tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := names.SetReleasedOn(ctx, tag.ID, &released); err != nil {
		t.Fatal(err)
	}
	b := httpapitest.Build{Product: "mine", BranchOrTag: name, Variant: "broadcom"}
	root := graph.Described{Purl: "pkg:generic/mine-" + name + "@1.0", Name: "mine-" + name, Version: "1.0"}
	_, scan := r.Shipped(t, b, "release-"+name, graph.Snapshot{Root: root})
	if err := ingest.NewStore(r.DB.DB).Made(ctx, scan, 1, 1, root.Name); err != nil {
		t.Fatal(err)
	}
	if doc != "" {
		httpapitest.ApplyRunAt(t, r, b, "codeql/default", time.Now().UTC().Add(-time.Hour), doc)
	}
}

type releasesRead struct {
	Releases []struct {
		BranchOrTag      string         `json:"branch_or_tag"`
		Cut              string         `json:"cut"`
		NotFixed         int            `json:"not_fixed"`
		ByTier           map[string]int `json:"by_tier"`
		Open             int            `json:"open"`
		Dismissed        int            `json:"dismissed"`
		NotSecurity      int            `json:"not_security"`
		NoLongerDetected int            `json:"no_longer_detected"`
	} `json:"releases"`
}

// Releases in the order they went out, never analyzed ones absent, an
// analyzed one holding nothing at zero.
func TestCodeFindingsByReleaseFollowTheTagsInOrder(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		day := func(s string) time.Time {
			at, err := time.Parse(time.DateOnly, s)
			if err != nil {
				t.Fatal(err)
			}
			return at
		}
		two := httpapitest.OtherToolRun("codeql", "overflow", "787", "src/x.c", 5, 9)
		one := httpapitest.OtherToolRun("codeql", "overflow", "787", "src/x.c", 5)
		// Declared out of the order they went out.
		tagged(t, r, "v1.1", day("2026-03-01"), one)
		tagged(t, r, "v1.0", day("2026-01-01"), two)
		tagged(t, r, "v1.2", day("2026-05-01"), noResults(one))
		tagged(t, r, "v0.9", day("2025-10-01"), "")
		// v1.0 analyzed again, comparably, with nothing found.
		httpapitest.ApplyRunAt(t, r, httpapitest.Build{Product: "mine", BranchOrTag: "v1.0", Variant: "broadcom"},
			"codeql/default", time.Now().UTC().Add(-30*time.Minute), noResults(two))

		var got releasesRead
		httpapitest.Read(t, r, "security-testing-reader", releasesOf, &got)
		var order []string
		for _, each := range got.Releases {
			order = append(order, each.BranchOrTag+"@"+each.Cut)
		}
		if strings.Join(order, " ") != "v1.0@2026-01-01 v1.1@2026-03-01 v1.2@2026-05-01" {
			t.Fatalf("the releases are %v; want v1.0, v1.1, v1.2 and no v0.9", order)
		}
		first, second, third := got.Releases[0], got.Releases[1], got.Releases[2]
		if first.NotFixed != 2 || first.ByTier["memory-safety"] != 2 || first.NoLongerDetected != 2 || first.Open != 0 {
			t.Errorf("v1.0 is %+v; want two not fixed, both no longer detected", first)
		}
		if second.NotFixed != 1 || second.Open != 1 || second.Dismissed != 0 {
			t.Errorf("v1.1 is %+v; want one open", second)
		}
		if third.NotFixed != 0 || third.ByTier["memory-safety"] != 0 {
			t.Errorf("v1.2 is %+v; want a point at zero", third)
		}

		var items struct {
			Items []struct {
				Occurrence string `json:"occurrence"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "code-finding-handler", "/v1/products/mine/code-findings?branch_or_tag=v1.1&variant=broadcom", &items)
		if len(items.Items) != 1 {
			t.Fatalf("v1.1's queue is %+v", items)
		}
		decided(t, r, "/v1/products/mine/branches-and-tags/v1.1/variants/broadcom/code-findings/"+items.Items[0].Occurrence,
			dismissal, true)
		httpapitest.Read(t, r, "security-testing-reader", releasesOf, &got)
		if second := got.Releases[1]; second.NotFixed != 1 || second.Dismissed != 1 || second.Open != 0 {
			t.Errorf("v1.1 dismissed is %+v; want it still not fixed, and dismissed", second)
		}
		// The decision is the occurrence's, so v1.0's line 5 reads it over
		// its absence.
		if first := got.Releases[0]; first.Dismissed != 1 || first.NoLongerDetected != 1 {
			t.Errorf("v1.0 is %+v; want one dismissed and one no longer detected", first)
		}
		// Not a security issue is its own count, apart from dismissed, as
		// the queue lists it apart.
		httpapitest.Read(t, r, "code-finding-handler",
			"/v1/products/mine/code-findings?branch_or_tag=v1.0&variant=broadcom&state=no-longer-detected", &items)
		if len(items.Items) != 1 {
			t.Fatalf("v1.0's no longer detected are %+v", items)
		}
		decided(t, r, "/v1/products/mine/branches-and-tags/v1.0/variants/broadcom/code-findings/"+items.Items[0].Occurrence,
			`{"outcome":"not-security","reasoning":"only the test harness reaches it"}`, true)
		httpapitest.Read(t, r, "security-testing-reader", releasesOf, &got)
		if first := got.Releases[0]; first.NotFixed != 2 || first.Dismissed != 1 || first.NotSecurity != 1 || first.NoLongerDetected != 0 {
			t.Errorf("v1.0 is %+v; want one dismissed and one not a security issue", first)
		}
		httpapitest.Read(t, r, "security-testing-reader", releasesOf+"?releases=2", &got)
		if len(got.Releases) != 2 || got.Releases[0].BranchOrTag != "v1.1" {
			t.Errorf("the newest two are %+v; want v1.1 and v1.2", got.Releases)
		}
	})
}

// Every figure and its file are at security testing visibility: refused to a
// reader of the product holding none before a name is resolved, and counted
// in the data layer over what the reader reads.
func TestWhoMayReadTheSecurityTestingFigures(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		const (
			build   = "?branch_or_tag=master&variant=broadcom"
			beneath = build + "&beneath=libmine1"
			absent  = build + "&beneath=nosuch"
		)
		for _, figure := range []struct {
			path    string
			beneath bool
		}{
			{judgeOf, true}, {fixOf, true}, {precisionOf, true}, {coverageOf, false}, {releasesOf, false},
		} {
			theirs := strings.Replace(figure.path, "/mine/", "/theirs/", 1)
			cases := []struct {
				who  string
				path string
				want int
			}{
				{"", figure.path, http.StatusUnauthorized},
				{"security-testing-reader", figure.path, http.StatusOK},
				{"security-testing-triager", figure.path, http.StatusOK},
				{"code-finding-handler", figure.path, http.StatusOK},
				{"reader", figure.path, http.StatusForbidden},
				{"private", figure.path, http.StatusForbidden},
				{"approver", figure.path, http.StatusNotFound},
				{"outsider", figure.path, http.StatusNotFound},
				{"security-testing-reader", theirs, http.StatusNotFound},
				{"outsider", theirs, http.StatusForbidden},

				{"", figure.path + ".csv", http.StatusUnauthorized},
				{"security-testing-reader", figure.path + ".csv", http.StatusOK},
				{"security-testing-reader", figure.path + ".json", http.StatusOK},
				{"reader", figure.path + ".csv", http.StatusForbidden},
				{"private", figure.path + ".json", http.StatusForbidden},
				{"approver", figure.path + ".csv", http.StatusNotFound},
			}
			if figure.beneath {
				cases = append(cases, []struct {
					who  string
					path string
					want int
				}{
					{"security-testing-reader", figure.path + beneath, http.StatusOK},
					{"security-testing-reader", figure.path + absent, http.StatusNotFound},
					// Authorized before the name is resolved: a name held and
					// a name not held are refused alike.
					{"reader", figure.path + beneath, http.StatusForbidden},
					{"reader", figure.path + absent, http.StatusForbidden},
					{"outsider", figure.path + absent, http.StatusNotFound},
				}...)
			}
			for _, c := range cases {
				if got := httpapitest.AsPerson(t, r, c.who, http.MethodGet, c.path, ""); got.Code != c.want {
					t.Errorf("%q GET %s = %d, want %d: %s", c.who, c.path, got.Code, c.want, got.Body.String())
				}
			}
		}

		// semgrep's code finding disclosed: counted for somebody reading
		// disclosed work beside security testing material, and not for
		// somebody reading security testing material alone.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"visibility" = ?`, access.Public).
			Where(`"kind" = ?`, kind.Analysis).
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" LIKE ?)`, "semgrep/%").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			who     string
			waiting int
			semgrep bool
		}{
			{"security-testing-reader", 1, false},
			{"code-finding-handler", 2, true},
		} {
			var judged judgingRead
			httpapitest.Read(t, r, c.who, judgeOf+"?weeks=2", &judged)
			waiting := 0
			for _, aged := range judged.Waiting {
				waiting += aged.Waiting
			}
			if waiting != c.waiting {
				t.Errorf("%s reads %d waiting; want %d", c.who, waiting, c.waiting)
			}
			var precise precisionRead
			httpapitest.Read(t, r, c.who, precisionOf, &precise)
			if (precise.series("semgrep/default").Series != "absent") != c.semgrep {
				t.Errorf("%s reads semgrep as %+v; want it counted %v", c.who, precise.series("semgrep/default"), c.semgrep)
			}
			w := httpapitest.AsPerson(t, r, c.who, http.MethodGet, precisionOf+".csv", "")
			if strings.Contains(w.Body.String(), "series,semgrep/default") != c.semgrep {
				t.Errorf("%s's precision file reads %s; want semgrep counted %v", c.who, w.Body.String(), c.semgrep)
			}
		}
	})
}

// A figure's file states what it covers where the query leaves the default to
// decide it: the weeks of a window, and the releases of a release line.
func TestAFigureFileStatesWhatItCovers(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		for _, c := range []struct{ path, csv, json string }{
			{judgeOf, "# weeks,13", `"weeks":"4"`},
			{fixOf, "# weeks,13", `"weeks":"4"`},
			{coverageOf, "# weeks,13", `"weeks":"4"`},
			{releasesOf, "# releases,12", `"releases":"4"`},
		} {
			asked := "?weeks=4"
			if c.path == releasesOf {
				asked = "?releases=4"
			}
			if w := httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet, c.path+".csv", ""); !strings.Contains(w.Body.String(), c.csv) {
				t.Errorf("%s.csv reads %s; want %q", c.path, w.Body.String(), c.csv)
			}
			if w := httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet, c.path+".json"+asked, ""); !strings.Contains(w.Body.String(), c.json) {
				t.Errorf("%s.json%s reads %s; want %q", c.path, asked, w.Body.String(), c.json)
			}
		}
	})
}
