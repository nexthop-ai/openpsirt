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

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// taggedLeak is the seeded run, the leak's last place being src/b.c line 3,
// the leak's rule tagged with the weakness CWE-tag.
func taggedLeak(tag string) string {
	return strings.Replace(httpapitest.CodeFindingRunAt(12), `{"id":"leak"}`,
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
	doc := strings.Replace(httpapitest.CodeFindingRunAt(12), `"results":[`, `"results":[`+results, 1)
	return strings.Replace(doc, `"rules":[{"id":"leak"},{"id":"overflow"}]`,
		`"rules":[{"id":"leak","properties":{"tags":["external/cwe/cwe-`+leakTag+`"]}},`+
			`{"id":"overflow","properties":{"tags":["external/cwe/cwe-`+overflowTag+`"]}}]`, 1)
}

// kinOf is the code findings a code finding's evidence says are one flaw with it, or may be.
func kinOf(t *testing.T, r *httpapitest.Reach, occurrence string) []struct {
	Occurrence string `json:"occurrence"`
	Line       int    `json:"line"`
	Same       bool   `json:"same"`
} {
	t.Helper()
	var got struct {
		Kin []struct {
			Occurrence string `json:"occurrence"`
			Line       int    `json:"line"`
			Same       bool   `json:"same"`
		} `json:"kin"`
	}
	httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence, &got)
	return got.Kin
}

func TestASecondAnalyzerReportingTheSameFlawGroupsItAndSortsItFirst(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		// CWE-416 and CWE-787 are both the bounds family. The overflow a
		// line past the leak's last place is the same flaw, the one nine
		// past possibly is, and the one twelve past is not.
		overflowsBesideTheLeak(t, r, "416", "787", 4, 12, 15)
		kin := kinOf(t, r, occurrence)
		if len(kin) != 2 || !kin[0].Same || kin[0].Line != 4 || kin[1].Same || kin[1].Line != 12 {
			t.Fatalf("the leak's kin are %+v; want the overflow on line 4 the same and line 12 possibly", kin)
		}
		// The queue puts the flaw two analyzers report above the one only
		// one does.
		queue := codeFindingsOf(t, r, "security-testing-reader", "")
		if len(queue.Items) != 4 {
			t.Fatalf("the queue is %+v; want the leak and three overflows", queue.Items)
		}
		top := map[string]bool{queue.Items[0].Occurrence: true, queue.Items[1].Occurrence: true}
		if !top[occurrence] || !top[kin[0].Occurrence] {
			t.Errorf("the queue is %+v; want the leak and the overflow on line 4 first", queue.Items)
		}
		// The overflows of one rule are never one flaw with each other.
		for _, k := range kinOf(t, r, kin[0].Occurrence) {
			if k.Occurrence != occurrence {
				t.Errorf("the overflow on line 4 is grouped with %+v of its own rule", k)
			}
		}
	})
}

func TestASecondAnalyzerSortsAFlawFirstWhateverNarrowsTheList(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		// cppcheck reports the leak's flaw a line past its last place. Then
		// the seeded series' next run reports an overflow of the leak's
		// weakness alone in another file, newer than the leak.
		overflowsBesideTheLeak(t, r, "416", "416", 4)
		alone := strings.Replace(taggedLeak("416"), `{"id":"overflow"}`,
			`{"id":"overflow","properties":{"tags":["external/cwe/cwe-416"]}}`, 1)
		alone = strings.Replace(alone, `"results":[`, `"results":[{"ruleId":"overflow","message":{"text":"n overflows"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/z.c","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":50}}}]},`, 1)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-30*time.Minute), alone)
		// Narrowed to the seeded series, the list holds neither cppcheck's
		// code finding nor anything else to sort the leak first by.
		queue := codeFindingsOf(t, r, "security-testing-reader", "?series=clang-tidy/default")
		if len(queue.Items) != 2 || queue.Items[0].Occurrence != occurrence || queue.Items[1].Path != "src/z.c" {
			t.Errorf("the seeded series' queue is %+v; want the leak cppcheck also reports first, then the newer overflow", queue.Items)
		}
		// cppcheck's code finding closed, the leak is one analyzer's again.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).Set(`"closed_at" = ?`, time.Now().UTC()).
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = 'cppcheck/overflow')`).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		queue = codeFindingsOf(t, r, "security-testing-reader", "?series=clang-tidy/default")
		if len(queue.Items) != 2 || queue.Items[0].Path != "src/z.c" || queue.Items[1].Occurrence != occurrence {
			t.Errorf("the seeded series' queue is %+v; want the newer overflow first once cppcheck's code finding closed", queue.Items)
		}
	})
}

func TestAFixedCodeFindingASecondAnalyzerStillReportsSortsFirst(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		// cppcheck reports the leak's flaw a line past its last place, and
		// the seeded series' next run an overflow of the leak's weakness
		// alone in another file, newer than the leak.
		overflowsBesideTheLeak(t, r, "416", "416", 4)
		alone := strings.Replace(taggedLeak("416"), `{"id":"overflow"}`,
			`{"id":"overflow","properties":{"tags":["external/cwe/cwe-416"]}}`, 1)
		alone = strings.Replace(alone, `"results":[`, `"results":[{"ruleId":"overflow","message":{"text":"n overflows"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/z.c","uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":50}}}]},`, 1)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-30*time.Minute), alone)
		closed := func(where string) {
			t.Helper()
			if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).Set(`"closed_at" = ?`, time.Now().UTC()).
				Where(`"kind" = ?`, kind.Analysis).Where(`"closed_at" IS NULL`).
				Where(`"vulnerability_id" ` + where + ` (SELECT "id" FROM "vulnerability" WHERE "identifier" = 'cppcheck/overflow')`).
				Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		// The seeded series' code findings fixed, cppcheck's still open
		// agrees with the leak, which the fixed list sorts first.
		closed("NOT IN")
		fixed := codeFindingsOf(t, r, "security-testing-reader", "?state=fixed")
		if len(fixed.Items) != 2 || fixed.Items[0].Occurrence != occurrence || fixed.Items[1].Path != "src/z.c" {
			t.Errorf("the fixed list is %+v; want the leak cppcheck still reports first, then the newer overflow", fixed.Items)
		}
		// cppcheck's code finding fixed too, nothing open agrees with the
		// leak, and the newer overflow comes first.
		closed("IN")
		fixed = codeFindingsOf(t, r, "security-testing-reader", "?state=fixed")
		var order []string
		for _, item := range fixed.Items {
			order = append(order, item.Path)
		}
		if len(fixed.Items) != 3 || fixed.Items[0].Path != "src/z.c" {
			t.Errorf("the fixed list is %v; want the newer overflow first once cppcheck's code finding is fixed", order)
		}
	})
}

func TestClangsCheckersRunByClangTidyAreNotASecondAnalyzer(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		// clang and clang-tidy both report clang's leak checker on one line,
		// one rule in one family.
		now := time.Now().UTC()
		httpapitest.ApplyRunIn(t, r, "clang/default", now.Add(-90*time.Minute),
			httpapitest.OtherToolRun("clang", "unix.Malloc", "401", "src/c.c", 7))
		httpapitest.ApplyRunIn(t, r, "clang-tidy/analyzer", now.Add(-80*time.Minute),
			httpapitest.OtherToolRun("clang-tidy", "clang-analyzer-unix.Malloc", "401", "src/c.c", 7))
		var both []string
		for _, codeFinding := range codeFindingsOf(t, r, "security-testing-reader", "").Items {
			if codeFinding.Path == "src/c.c" {
				both = append(both, codeFinding.Occurrence)
			}
		}
		if len(both) != 2 {
			t.Fatalf("the queue holds %v at src/c.c; want the two leak results", both)
		}
		for _, occurrence := range both {
			if kin := kinOf(t, r, occurrence); len(kin) != 0 {
				t.Errorf("code finding %s has kin %+v; want none of clang's own checker", occurrence, kin)
			}
		}
	})
}

func TestTwoRulesOfOneAnalyzerOnOneLineAreNotOneFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		// The seeded analyzer reports an overflow at the leak's last place,
		// both rules in one family.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), oneToolOverflows("416", "787", 3))
		if kin := kinOf(t, r, occurrence); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none of its own analyzer", kin)
		}
	})
}

func TestCodeFindingsOfUnrelatedWeaknessesAreNotOneFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		// CWE-563 is dead code, which is no family of CWE-787's.
		overflowsBesideTheLeak(t, r, "563", "787", 3)
		if kin := kinOf(t, r, occurrence); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none", kin)
		}
		// Nor does the queue sort the leak above a newer code finding of its
		// weakness that no second analyzer reports.
		sortsBelowANewerOne(t, r, occurrence, "563")
	})
}

func TestASecondAnalyzerOnAnotherBuildIsNotTheSameFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		// cppcheck reports the leak's flaw a line past its last place, on
		// another variant's build.
		r.AlsoIn(t, "mellanox")
		mellanox := httpapitest.Build{Product: "mine", BranchOrTag: "master", Variant: "mellanox"}
		_, scan := r.Shipped(t, mellanox, "made-mellanox", graph.Snapshot{Root: httpapitest.SeededRoot})
		if err := ingest.NewStore(r.DB.DB).Made(t.Context(), scan, 1, 1, httpapitest.SeededRoot.Name); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		httpapitest.ApplyRun(t, r, now.Add(-90*time.Minute), taggedLeak("416"))
		httpapitest.ApplyRunAt(t, r, mellanox, "cppcheck/default", now.Add(-70*time.Minute),
			httpapitest.OtherToolRun("cppcheck", "overflow", "787", "src/b.c", 4))
		if kin := kinOf(t, r, occurrence); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none on another build", kin)
		}
		sortsBelowANewerOne(t, r, occurrence, "416")
	})
}

func TestCodeFindingsWithoutALineAreNotOneFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		// Two analyzers report an overflow of one weakness in src/y.c,
		// neither saying on which line.
		lineless := func(tool string) string {
			return strings.Replace(httpapitest.OtherToolRun(tool, "overflow", "416", "src/y.c", 1),
				`,"region":{"startLine":1}`, "", 1)
		}
		now := time.Now().UTC()
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", now.Add(-70*time.Minute), lineless("cppcheck"))
		httpapitest.ApplyRunIn(t, r, "semgrep/default", now.Add(-60*time.Minute), lineless("semgrep"))
		occurrence := ""
		for _, item := range codeFindingsOf(t, r, "security-testing-reader", "").Items {
			if item.Path == "src/y.c" {
				occurrence = item.Occurrence
			}
		}
		if occurrence == "" {
			t.Fatal("neither overflow in src/y.c is listed")
		}
		sortsBelowANewerOne(t, r, occurrence, "416")
	})
}

// sortsBelowANewerOne has the seeded analyzer report, after everything
// else, an overflow tagged with the weakness CWE-tag in src/z.c, and checks
// that the queue sorts the code finding at occurrence below it, as one no
// second analyzer reports.
func sortsBelowANewerOne(t *testing.T, r *httpapitest.Reach, occurrence, tag string) {
	t.Helper()
	alone := strings.Replace(taggedLeak(tag), `{"id":"overflow"}`,
		`{"id":"overflow","properties":{"tags":["external/cwe/cwe-`+tag+`"]}}`, 1)
	alone = strings.Replace(alone, `"results":[`, `"results":[{"ruleId":"overflow","message":{"text":"n overflows"},`+
		`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/z.c","uriBaseId":"SRCROOT"},`+
		`"region":{"startLine":50}}}]},`, 1)
	httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-30*time.Minute), alone)
	newer, older := -1, -1
	for i, item := range codeFindingsOf(t, r, "security-testing-reader", "").Items {
		switch {
		case item.Path == "src/z.c":
			newer = i
		case item.Occurrence == occurrence:
			older = i
		}
	}
	if newer < 0 || older < 0 || newer > older {
		t.Errorf("the newer code finding is at %d and the older one at %d; want the newer one first", newer, older)
	}
}

func TestCodeFindingsInTwoFilesAreNotOneFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		overflowsIn(t, r, "src/c.c", "416", "787", 3)
		if kin := kinOf(t, r, occurrence); len(kin) != 0 {
			t.Errorf("the leak's kin are %+v; want none in another file", kin)
		}
		sortsBelowANewerOne(t, r, occurrence, "416")
	})
}

// decideCodeFinding records a decision about a code finding as the security testing triager, and the
// decision it made.
func decideCodeFinding(t *testing.T, r *httpapitest.Reach, occurrence, body string) core.DecisionOccurrenceBody {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, fmt.Sprintf(codeFindingDecisionAt, occurrence), body)
	if got.Code != http.StatusCreated {
		t.Fatalf("deciding %s answered %d: %s", occurrence, got.Code, got.Body)
	}
	var decided core.DecisionOccurrenceBody
	if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
		t.Fatal(err)
	}
	return decided
}

// besideTheLeak is the seeded code finding and its kin once overflows are reported
// at the lines of src/b.c given, in the bounds family.
func besideTheLeak(t *testing.T, r *httpapitest.Reach, lines ...int) (string, []string) {
	t.Helper()
	occurrence := httpapitest.SeededCodeFinding(t, r)
	overflowsBesideTheLeak(t, r, "416", "787", lines...)
	var kin []string
	for _, k := range kinOf(t, r, occurrence) {
		kin = append(kin, k.Occurrence)
	}
	return occurrence, kin
}

func TestOneDecisionAnswersEveryCodeFindingThatIsTheSameFlaw(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4, 12)
		if len(kin) != 2 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4 and possibly line 12", kin)
		}
		decided := decideCodeFinding(t, r, occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked by the caller"}`)
		httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`)
		if got := codeFindingState(t, r, occurrence); got != "dismissed" {
			t.Errorf("the code finding decided is %q; want dismissed", got)
		}
		if got := codeFindingState(t, r, kin[0]); got != "dismissed" {
			t.Errorf("the overflow that is the same flaw is %q; want it answered by the one approval", got)
		}
		// A code finding that is possibly the same flaw is left to be judged.
		if got := codeFindingState(t, r, kin[1]); got != "open" {
			t.Errorf("the overflow that is possibly the same flaw is %q; want it open", got)
		}
	})
}

func TestACodeFindingOfAGroupAlreadyAnsweredKeepsItsAnswer(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// The leak is answered before the overflow is reported beside it.
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		overflowsBesideTheLeak(t, r, "416", "787", 4)
		kin := kinOf(t, r, occurrence)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %+v; want the overflow on line 4", kin)
		}
		decided := decideCodeFinding(t, r, kin[0].Occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"never reached"}`)
		httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`)
		if got := codeFindingState(t, r, occurrence); got != "confirmed" {
			t.Errorf("the leak confirmed first is %q; want it confirmed still", got)
		}
		if got := codeFindingState(t, r, kin[0].Occurrence); got != "dismissed" {
			t.Errorf("the overflow decided is %q; want dismissed", got)
		}
	})
}

func TestACodeFindingOfAGroupWaitingOnADecisionKeepsIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decideCodeFinding(t, r, occurrence, `{"outcome":"not-security","reasoning":"a style finding"}`)
		overflowsBesideTheLeak(t, r, "416", "787", 4)
		kin := kinOf(t, r, occurrence)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %+v; want the overflow on line 4", kin)
		}
		decideCodeFinding(t, r, kin[0].Occurrence, `{"outcome":"confirmed","reasoning":"the length is attacker controlled"}`)
		if got := codeFindingState(t, r, occurrence); got != "open" {
			t.Errorf("the leak whose decision waits is %q; want it waiting still", got)
		}
	})
}

func TestACodeFindingOfAGroupUnderASuppressionRuleKeepsIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		rule := proposeSuppressionRule(t, r, `{"rule":"cppcheck/overflow","prefix":"src/b.c",`+
			`"reason":"false_positive","reasoning":"the buffer is sized by the generator"}`)
		approveSuppressionRule(t, r, rule.ID)
		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if got := codeFindingState(t, r, kin[0]); got != "dismissed" {
			t.Errorf("the overflow a suppression rule dismisses is %q; want it dismissed still", got)
		}
		if got := codeFindingState(t, r, occurrence); got != "confirmed" {
			t.Errorf("the code finding decided is %q; want confirmed", got)
		}
	})
}

func TestACodeFindingOfAGroupNobodyMayReadIsNotDecided(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		if _, err := r.DB.DB.NewUpdate().Table("finding").Set(`"visibility" = 'private'`).
			Where(`"occurrence_identity" = ?`, kin[0]).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		var decided int
		if err := r.DB.DB.NewSelect().Table("decision_occurrence").ColumnExpr("COUNT(*)").
			Where(`"occurrence_identity" = ?`, kin[0]).Scan(t.Context(), &decided); err != nil {
			t.Fatal(err)
		}
		if decided != 0 {
			t.Errorf("a decision by somebody who cannot read the overflow was recorded at it %d times", decided)
		}
	})
}

func TestACodeFindingOfAGroupThatIsFixedIsNotDecided(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		if _, err := r.DB.DB.NewUpdate().Table("finding").Set(`"closed_at" = ?`, time.Now().UTC()).
			Where(`"occurrence_identity" = ?`, kin[0]).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if got := codeFindingState(t, r, kin[0]); got != "fixed" {
			t.Errorf("the overflow fixed is %q; want it fixed still", got)
		}
		var decided int
		if err := r.DB.DB.NewSelect().Table("decision_occurrence").ColumnExpr("COUNT(*)").
			Where(`"occurrence_identity" = ?`, kin[0]).Scan(t.Context(), &decided); err != nil {
			t.Fatal(err)
		}
		if decided != 0 {
			t.Errorf("a decision was recorded at the fixed overflow %d times", decided)
		}
	})
}

// recordedAsFlawAs is a code finding's state and the flaw it is recorded as, as somebody
// reading undisclosed work reads it.
func recordedAsFlawAs(t *testing.T, r *httpapitest.Reach, occurrence string) (string, string, bool) {
	t.Helper()
	var got struct {
		State          string `json:"state"`
		RecordedAsFlaw *struct {
			Flaw                 string `json:"flaw"`
			IncludedInDisclosure bool   `json:"included_in_disclosure"`
		} `json:"recorded_as_flaw"`
	}
	httpapitest.Read(t, r, "code-finding-handler", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence, &got)
	if got.RecordedAsFlaw == nil {
		return got.State, "", false
	}
	return got.State, got.RecordedAsFlaw.Flaw, got.RecordedAsFlaw.IncludedInDisclosure
}

func TestARecordAsFlawLinksEveryCodeFindingItsConfirmationCovers(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4", kin)
		}
		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"p leaks and n overflows, one flaw"}`)
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"
		var offer struct {
			Together  int `json:"together"`
			Discloses struct {
				Paths []string `json:"paths"`
			} `json:"discloses"`
		}
		httpapitest.Read(t, r, "code-finding-handler", at+occurrence+"/flaw", &offer)
		if offer.Together != 1 || len(offer.Discloses.Paths) != 2 {
			t.Errorf("the flaw record offers %+v; want the overflow with it, and both files disclosed", offer)
		}
		got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, at+occurrence+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks","include_in_disclosure":true}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the flaw record answered %d: %s", got.Code, got.Body)
		}
		_, flaw, _ := recordedAsFlawAs(t, r, occurrence)
		if state, as, moved := recordedAsFlawAs(t, r, kin[0]); state != "recorded-as-flaw" || as != flaw || !moved {
			t.Errorf("the overflow confirmed with the leak is %s as %q, moved %v; want it recorded as %s and moved",
				state, as, moved, flaw)
		}
		// One flaw is recorded once.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, at+kin[0]+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"n overflows"}`), http.StatusConflict)
		// The code findings of one flaw move together.
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete, at+kin[0]+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Fatalf("taking the overflow out of the case answered %d: %s", got.Code, got.Body)
		}
		if _, _, moved := recordedAsFlawAs(t, r, occurrence); moved {
			t.Errorf("the leak stayed in the case its overflow was taken out of")
		}
	})
}

func TestAnUndoneRecordAsFlawIsTrailedUnderEachCodeFindingsOwnName(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4", kin)
		}
		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"p leaks and n overflows, one flaw"}`)
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, at+occurrence+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the flaw record answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, at+kin[0]+"/collaborators/embargo-reader", ""); got.Code != http.StatusNoContent {
			t.Fatalf("granting the overflow answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, at+occurrence+"/flaw/withdrawal",
			`{"because":"two flaws after all"}`); got.Code != http.StatusNoContent {
			t.Fatalf("undoing the flaw record answered %d: %s", got.Code, got.Body)
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
			case row.Became == "flaw record undone":
				undone = append(undone, row.About)
			case strings.HasSuffix(row.About, " · embargo-reader") && row.Became == "":
				withdrawn = append(withdrawn, row.About)
			}
		}
		slices.Sort(undone)
		if len(undone) != 2 || !strings.HasSuffix(undone[0], "clang-tidy/leak") || !strings.HasSuffix(undone[1], "cppcheck/overflow") {
			t.Errorf("the undo was trailed as %q; want one row under each code finding's name", undone)
		}
		if len(withdrawn) != 1 || !strings.Contains(withdrawn[0], "cppcheck/overflow") {
			t.Errorf("the overflow's grant ended trailed as %q; want it under the overflow's name", withdrawn)
		}
	})
}
