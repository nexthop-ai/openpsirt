// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// taggedLeak is the seeded run, the leak's last place being src/b.c line 3,
// the leak's rule tagged with the weakness CWE-tag.
func taggedLeak(tag string) string {
	return strings.Replace(httpapitest.LeadRunAt(12), `{"id":"leak"}`,
		`{"id":"leak","properties":{"tags":["external/cwe/cwe-`+tag+`"]}}`, 1)
}

// overflowsBesideTheLeak reports the seeded leak tagged leakTag, and a
// second analyzer, cppcheck, reporting an overflow tagged overflowTag at each
// line of src/b.c given.
func overflowsBesideTheLeak(t *testing.T, r *httpapitest.Reach, leakTag, overflowTag string, lines ...int) {
	t.Helper()
	overflowsIn(t, r, "src/b.c", leakTag, overflowTag, lines...)
}

// overflowsIn is overflowsBesideTheLeak reporting the overflows in file.
func overflowsIn(t *testing.T, r *httpapitest.Reach, file, leakTag, overflowTag string, lines ...int) {
	t.Helper()
	now := time.Now().UTC()
	httpapitest.ApplyRun(t, r, now.Add(-90*time.Minute), taggedLeak(leakTag))
	httpapitest.ApplyRunIn(t, r, "cppcheck/default", now.Add(-70*time.Minute),
		httpapitest.OtherToolRun("cppcheck", "overflow", overflowTag, file, lines...))
}

// oneToolOverflows is the seeded run with the seeded analyzer also reporting
// an overflow at each line of src/b.c given, the leak's rule tagged leakTag
// and the overflow's overflowTag.
func oneToolOverflows(leakTag, overflowTag string, lines ...int) string {
	results := ""
	for _, line := range lines {
		results += `{"ruleId":"overflow","message":{"text":"n overflows"},` +
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/b.c","uriBaseId":"SRCROOT"},` +
			`"region":{"startLine":` + strconv.Itoa(line) + `}}}]},`
	}
	doc := strings.Replace(httpapitest.LeadRunAt(12), `"results":[`, `"results":[`+results, 1)
	return strings.Replace(doc, `"rules":[{"id":"leak"},{"id":"overflow"}]`,
		`"rules":[{"id":"leak","properties":{"tags":["external/cwe/cwe-`+leakTag+`"]}},`+
			`{"id":"overflow","properties":{"tags":["external/cwe/cwe-`+overflowTag+`"]}}]`, 1)
}

// kinOf is the leads a lead's evidence says are one flaw with it, or may be.
func kinOf(t *testing.T, r *httpapitest.Reach, place string) []struct {
	Place string `json:"place"`
	Line  int    `json:"line"`
	Same  bool   `json:"same"`
} {
	t.Helper()
	var got struct {
		Kin []struct {
			Place string `json:"place"`
			Line  int    `json:"line"`
			Same  bool   `json:"same"`
		} `json:"kin"`
	}
	httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+place, &got)
	return got.Kin
}

func TestASecondAnalyzerReportingTheSameFlawGroupsItAndSortsItFirst(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		// CWE-416 and CWE-787 are both the bounds family. The overflow a
		// line past the leak's last place is the same flaw, the one nine
		// past possibly is, and the one twelve past is not.
		overflowsBesideTheLeak(t, r, "416", "787", 4, 12, 15)
		kin := kinOf(t, r, place)
		if len(kin) != 2 || !kin[0].Same || kin[0].Line != 4 || kin[1].Same || kin[1].Line != 12 {
			t.Fatalf("the leak's kin are %+v; want the overflow on line 4 the same and line 12 possibly", kin)
		}
		// The queue puts the flaw two analyzers report above the one only
		// one does.
		queue := leadsOf(t, r, "internal-reader", "")
		if len(queue.Items) != 4 {
			t.Fatalf("the queue is %+v; want the leak and three overflows", queue.Items)
		}
		top := map[string]bool{queue.Items[0].Place: true, queue.Items[1].Place: true}
		if !top[place] || !top[kin[0].Place] {
			t.Errorf("the queue is %+v; want the leak and the overflow on line 4 first", queue.Items)
		}
		// The overflows of one rule are never one flaw with each other.
		for _, k := range kinOf(t, r, kin[0].Place) {
			if k.Place != place {
				t.Errorf("the overflow on line 4 is grouped with %+v of its own rule", k)
			}
		}
	})
}

func TestClangsCheckersRunByClangTidyAreNotASecondAnalyzer(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		// clang and clang-tidy both report clang's leak checker on one line,
		// one rule in one family.
		now := time.Now().UTC()
		httpapitest.ApplyRunIn(t, r, "clang/default", now.Add(-90*time.Minute),
			httpapitest.OtherToolRun("clang", "unix.Malloc", "401", "src/c.c", 7))
		httpapitest.ApplyRunIn(t, r, "clang-tidy/analyzer", now.Add(-80*time.Minute),
			httpapitest.OtherToolRun("clang-tidy", "clang-analyzer-unix.Malloc", "401", "src/c.c", 7))
		var both []string
		for _, lead := range leadsOf(t, r, "internal-reader", "").Items {
			if lead.Path == "src/c.c" {
				both = append(both, lead.Place)
			}
		}
		if len(both) != 2 {
			t.Fatalf("the queue holds %v at src/c.c; want the two leak results", both)
		}
		for _, place := range both {
			if kin := kinOf(t, r, place); len(kin) != 0 {
				t.Errorf("lead %s has kin %+v; want none of clang's own checker", place, kin)
			}
		}
	})
}

func TestTwoRulesOfOneAnalyzerOnOneLineAreNotOneFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		// The seeded analyzer reports an overflow at the leak's last place,
		// both rules in one family.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), oneToolOverflows("416", "787", 3))
		if kin := kinOf(t, r, place); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none of its own analyzer", kin)
		}
	})
}

func TestLeadsOfUnrelatedWeaknessesAreNotOneFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		// CWE-563 is dead code, which is no family of CWE-787's.
		overflowsBesideTheLeak(t, r, "563", "787", 3)
		if kin := kinOf(t, r, place); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none", kin)
		}
	})
}

func TestLeadsInTwoFilesAreNotOneFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		overflowsIn(t, r, "src/c.c", "416", "787", 3)
		if kin := kinOf(t, r, place); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none in another file", kin)
		}
	})
}

// decideLead records a judgment about a lead as the internal triager, and the
// claim it made.
func decideLead(t *testing.T, r *httpapitest.Reach, place, body string) core.DecisionBody {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(leadDecisionAt, place), body)
	if got.Code != http.StatusCreated {
		t.Fatalf("deciding %s answered %d: %s", place, got.Code, got.Body)
	}
	var decided core.DecisionBody
	if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
		t.Fatal(err)
	}
	return decided
}

// besideTheLeak is the seeded lead and its kin once overflows are reported
// at the lines of src/b.c given, in the bounds family.
func besideTheLeak(t *testing.T, r *httpapitest.Reach, lines ...int) (string, []string) {
	t.Helper()
	place := httpapitest.SeededLead(t, r)
	overflowsBesideTheLeak(t, r, "416", "787", lines...)
	var kin []string
	for _, k := range kinOf(t, r, place) {
		kin = append(kin, k.Place)
	}
	return place, kin
}

func TestOneDecisionAnswersEveryLeadThatIsTheSameFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, kin := besideTheLeak(t, r, 4, 12)
		if len(kin) != 2 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4 and possibly line 12", kin)
		}
		decided := decideLead(t, r, place,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked by the caller"}`)
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.ClaimID), `{}`)
		if got := leadState(t, r, place); got != "dismissed" {
			t.Errorf("the lead decided is %q; want dismissed", got)
		}
		if got := leadState(t, r, kin[0]); got != "dismissed" {
			t.Errorf("the overflow that is the same flaw is %q; want it answered by the one approval", got)
		}
		// A lead that is possibly the same flaw is left to be judged.
		if got := leadState(t, r, kin[1]); got != "open" {
			t.Errorf("the overflow that is possibly the same flaw is %q; want it open", got)
		}
	})
}

func TestALeadOfAGroupAlreadyAnsweredKeepsItsAnswer(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// The leak is answered before the overflow is reported beside it.
		place := httpapitest.SeededLead(t, r)
		decideLead(t, r, place, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		overflowsBesideTheLeak(t, r, "416", "787", 4)
		kin := kinOf(t, r, place)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %+v; want the overflow on line 4", kin)
		}
		decided := decideLead(t, r, kin[0].Place,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"never reached"}`)
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.ClaimID), `{}`)
		if got := leadState(t, r, place); got != "confirmed" {
			t.Errorf("the leak confirmed first is %q; want it confirmed still", got)
		}
		if got := leadState(t, r, kin[0].Place); got != "dismissed" {
			t.Errorf("the overflow decided is %q; want dismissed", got)
		}
	})
}

func TestALeadOfAGroupWaitingOnAClaimKeepsIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		decideLead(t, r, place, `{"outcome":"not-security","reasoning":"a style finding"}`)
		overflowsBesideTheLeak(t, r, "416", "787", 4)
		kin := kinOf(t, r, place)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %+v; want the overflow on line 4", kin)
		}
		decideLead(t, r, kin[0].Place, `{"outcome":"confirmed","reasoning":"the length is attacker controlled"}`)
		if got := leadState(t, r, place); got != "open" {
			t.Errorf("the leak whose claim waits is %q; want it waiting still", got)
		}
	})
}

func TestALeadOfAGroupUnderAStandingRuleKeepsIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, kin := besideTheLeak(t, r, 4)
		rule := proposeLeadRule(t, r, `{"rule":"cppcheck/overflow","prefix":"src/b.c",`+
			`"reason":"false_positive","reasoning":"the buffer is sized by the generator"}`)
		approveLeadRule(t, r, rule.ID)
		decideLead(t, r, place, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if got := leadState(t, r, kin[0]); got != "dismissed" {
			t.Errorf("the overflow a standing rule dismisses is %q; want it dismissed still", got)
		}
		if got := leadState(t, r, place); got != "confirmed" {
			t.Errorf("the lead decided is %q; want confirmed", got)
		}
	})
}

func TestALeadOfAGroupNobodyMayReadIsNotDecided(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, kin := besideTheLeak(t, r, 4)
		if _, err := r.DB.DB.NewUpdate().Table("finding").Set(`"visibility" = 'private'`).
			Where(`"place_identity" = ?`, kin[0]).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		decideLead(t, r, place, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		var decided int
		if err := r.DB.DB.NewSelect().Table("decision").ColumnExpr("COUNT(*)").
			Where(`"place_identity" = ?`, kin[0]).Scan(t.Context(), &decided); err != nil {
			t.Fatal(err)
		}
		if decided != 0 {
			t.Errorf("a judgment by somebody who cannot read the overflow was recorded at it %d times", decided)
		}
	})
}

func TestALeadOfAGroupThatIsFixedIsNotDecided(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, kin := besideTheLeak(t, r, 4)
		if _, err := r.DB.DB.NewUpdate().Table("finding").Set(`"closed_at" = ?`, time.Now().UTC()).
			Where(`"place_identity" = ?`, kin[0]).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		decideLead(t, r, place, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if got := leadState(t, r, kin[0]); got != "fixed" {
			t.Errorf("the overflow fixed is %q; want it fixed still", got)
		}
		var decided int
		if err := r.DB.DB.NewSelect().Table("decision").ColumnExpr("COUNT(*)").
			Where(`"place_identity" = ?`, kin[0]).Scan(t.Context(), &decided); err != nil {
			t.Fatal(err)
		}
		if decided != 0 {
			t.Errorf("a judgment was recorded at the fixed overflow %d times", decided)
		}
	})
}

// handedOffAs is a lead's state and the flaw it is handed off as, as somebody
// reading undisclosed work reads it.
func handedOffAs(t *testing.T, r *httpapitest.Reach, place string) (string, string, bool) {
	t.Helper()
	var got struct {
		State   string `json:"state"`
		Handoff *struct {
			Flaw  string `json:"flaw"`
			Moved bool   `json:"moved"`
		} `json:"handoff"`
	}
	httpapitest.Read(t, r, "lead-handler", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+place, &got)
	if got.Handoff == nil {
		return got.State, "", false
	}
	return got.State, got.Handoff.Flaw, got.Handoff.Moved
}

func TestAHandOffLinksEveryLeadItsConfirmationCovers(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, kin := besideTheLeak(t, r, 4)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4", kin)
		}
		decideLead(t, r, place, `{"outcome":"confirmed","reasoning":"p leaks and n overflows, one flaw"}`)
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"
		var offer struct {
			Together  int `json:"together"`
			Discloses struct {
				Paths []string `json:"paths"`
			} `json:"discloses"`
		}
		httpapitest.Read(t, r, "lead-handler", at+place+"/flaw", &offer)
		if offer.Together != 1 || len(offer.Discloses.Paths) != 2 {
			t.Errorf("the hand-off offers %+v; want the overflow with it, and both files disclosed", offer)
		}
		got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, at+place+"/flaw",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks","move":true}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the hand-off answered %d: %s", got.Code, got.Body)
		}
		_, flaw, _ := handedOffAs(t, r, place)
		if state, as, moved := handedOffAs(t, r, kin[0]); state != "handed-off" || as != flaw || !moved {
			t.Errorf("the overflow confirmed with the leak is %s as %q, moved %v; want it handed off as %s and moved",
				state, as, moved, flaw)
		}
		// One flaw is recorded once.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, at+kin[0]+"/flaw",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"n overflows"}`), http.StatusConflict)
		// The leads of one flaw move together.
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodDelete, at+kin[0]+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Fatalf("taking the overflow out of the case answered %d: %s", got.Code, got.Body)
		}
		if _, _, moved := handedOffAs(t, r, place); moved {
			t.Errorf("the leak stayed in the case its overflow was taken out of")
		}
	})
}

func TestAnUndoneHandOffIsTrailedUnderEachLeadsOwnName(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, kin := besideTheLeak(t, r, 4)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4", kin)
		}
		decideLead(t, r, place, `{"outcome":"confirmed","reasoning":"p leaks and n overflows, one flaw"}`)
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, at+place+"/flaw",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the hand-off answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPut, at+kin[0]+"/collaborators/embargo-reader", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the overflow answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, at+place+"/flaw/withdrawal",
			`{"because":"two flaws after all"}`); got.Code != http.StatusNoContent {
			t.Fatalf("undoing the hand-off answered %d: %s", got.Code, got.Body)
		}
		var trail struct {
			Items []struct {
				About  string `json:"about"`
				Was    string `json:"was"`
				Became string `json:"became"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "admin", "/v1/administration/changes?kind=case&limit=100", &trail)
		var undone, withdrawn []string
		for _, row := range trail.Items {
			switch {
			case row.Became == "hand-off undone":
				undone = append(undone, row.About)
			case strings.HasSuffix(row.About, " · embargo-reader") && row.Became == "":
				withdrawn = append(withdrawn, row.About)
			}
		}
		slices.Sort(undone)
		if len(undone) != 2 || !strings.HasSuffix(undone[0], "clang-tidy/leak") || !strings.HasSuffix(undone[1], "cppcheck/overflow") {
			t.Errorf("the undo was trailed as %q; want one row under each lead's name", undone)
		}
		if len(withdrawn) != 1 || !strings.Contains(withdrawn[0], "cppcheck/overflow") {
			t.Errorf("the overflow's grant ended trailed as %q; want it under the overflow's name", withdrawn)
		}
	})
}
