// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

const codeFindingsAtMaster = "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"

// endMaster puts the seeded release past its end of life.
func endMaster(t *testing.T, r *httpapitest.Reach) {
	t.Helper()
	ended := time.Now().UTC().Add(-48 * time.Hour).Truncate(24 * time.Hour)
	if _, err := r.DB.DB.NewUpdate().TableExpr(`"branch_or_tag"`).Set(`"eol_on" = ?`, ended).
		Where(`"name" = ?`, "master").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// alsoOnV1 opens the code finding at an occurrence on a release v1, still in support, as
// well as on the seeded one.
func alsoOnV1(t *testing.T, r *httpapitest.Reach, occurrence string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	mine, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.DeclareBranchOrTag(ctx, mine.ID, "v1", catalog.Branch, nil); err != nil {
		t.Fatal(err)
	}
	other := r.BuildOf(t, httpapitest.Build{Product: "mine", BranchOrTag: "v1", Variant: "broadcom"})
	var codeFinding finding.Finding
	if err := r.DB.DB.NewSelect().Model(&codeFinding).Where(`"f"."occurrence_identity" = ?`, occurrence).
		Where(`"f"."closed_at" IS NULL`).Limit(1).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	codeFinding.ID, codeFinding.BuildID = 0, other
	if _, err := r.DB.DB.NewInsert().Model(&codeFinding).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// decisionsAt is how many rows were ever recorded at an occurrence.
func decisionsAt(t *testing.T, r *httpapitest.Reach, occurrence string) int {
	t.Helper()
	var n int
	if err := r.DB.DB.NewSelect().Table("decision_occurrence").ColumnExpr("COUNT(*)").
		Where(`"occurrence_identity" = ?`, occurrence).Scan(t.Context(), &n); err != nil {
		t.Fatal(err)
	}
	return n
}

// refusedAsEnded fails unless a request was refused because its code finding is past
// its end of life.
func refusedAsEnded(t *testing.T, what string, got *httptest.ResponseRecorder) {
	t.Helper()
	if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "end of life") {
		t.Errorf("%s past its end of life answered %d: %s; want 409 for the end of life", what, got.Code, got.Body)
	}
}

func TestACodeFindingPastItsEndOfLifeRefusesEveryChangeButAnAgreementAndAMove(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		kept, _ := httpapitest.RecordedCodeFinding(t, r, false)
		overflowsIn(t, r, "src/c.c", "416", "787", 3)
		var overflow string
		for _, item := range codeFindingsOf(t, r, "internal-reader", "?state=open").Items {
			if item.Occurrence != kept {
				overflow = item.Occurrence
			}
		}
		if overflow == "" {
			t.Fatal("the overflow in src/c.c did not open a code finding")
		}
		waiting := decideCodeFinding(t, r, overflow,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked by the caller"}`)
		// No longer detected, so a fixed closure is refused for nothing but the
		// end of life.
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.OtherToolRun("cppcheck", "overflow", "787", "src/c.c"))
		endMaster(t, r)

		refusedAsEnded(t, "a fixed closure", httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			codeFindingsAtMaster+overflow+"/fixed",
			httpapitest.FixedBody(t, r, codeFindingsAtMaster+overflow, "the bounds check landed")))
		refusedAsEnded(t, "a flaw record", httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost,
			codeFindingsAtMaster+overflow+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"n overflows","include_in_disclosure":false}`))

		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", waiting.DecisionID), `{}`); got.Code != http.StatusOK {
			t.Errorf("agreeing to a decision standing at a code finding past its end of life answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, codeFindingsAtMaster+kept+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
			t.Errorf("moving a code finding recorded as a flaw past its end of life answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestALapsedDecisionAtACodeFindingPastItsEndOfLifeIsNotReaffirmed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decided := decideCodeFinding(t, r, occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"freed by the caller"}`)
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRunAt(12))
		// Two lines down pairs it on its nearest line, which lapses it.
		httpapitest.ApplyRun(t, r, time.Now().UTC(), httpapitest.CodeFindingRunAt(14))
		if got := codeFindingState(t, r, occurrence); got == "dismissed" {
			t.Fatal("a dismissal paired only on its nearest line did not lapse")
		}
		if listed := toReaffirm(t, r, "internal-triager"); len(listed) != 1 {
			t.Fatalf("%d decisions are listed to re-affirm before the end of life; want the one lapsed, "+
				"so this checks nothing", len(listed))
		}
		endMaster(t, r)

		if listed := toReaffirm(t, r, "internal-triager"); len(listed) != 0 {
			t.Errorf("a decision at a code finding past its end of life alone is listed to re-affirm: %+v", listed)
		}
		var page struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "internal-triager", "/v1/to-reaffirm", &page)
		if page.Total != 0 {
			t.Errorf("the decisions to re-affirm total %d; want none", page.Total)
		}
		var decision struct {
			Reaffirmable bool `json:"reaffirmable"`
		}
		httpapitest.Read(t, r, "internal-triager", fmt.Sprintf("/v1/decisions/%d", decided.DecisionID), &decision)
		if decision.Reaffirmable {
			t.Error("a decision at a code finding past its end of life alone reads as re-affirmable")
		}
		refusedAsEnded(t, "re-affirming a decision", httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/reaffirmation", decided.DecisionID),
			`{"reasoning":"still freed by the caller after the move"}`))
		refusedAsEnded(t, "re-affirming decisions together", httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/reaffirmations",
			fmt.Sprintf(`{"decisions":[%d],"reasoning":"still freed by the caller after the move"}`, decided.DecisionID)))
		if got := codeFindingState(t, r, occurrence); got == "dismissed" {
			t.Errorf("a code finding past its end of life is %q after the refusals; want it as it stood", got)
		}
	})
}

func TestADecisionAboutACodeFindingStillInSupportReachesNoKinPastItsEndOfLife(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4", kin)
		}
		// The leak is also seen on a release still in support, and its kin
		// only on the seeded one.
		alsoOnV1(t, r, occurrence)
		endMaster(t, r)

		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if decided := decisionsAt(t, r, kin[0]); decided != 0 {
			t.Errorf("a decision was recorded %d times at kin seen only past its end of life", decided)
		}
	})
}

func TestAReaffirmationRemakesADecisionOnlyAtCodeFindingsStillInSupport(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4", kin)
		}
		decided := decideCodeFinding(t, r, occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked by the caller"}`)
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`)
		if got := decisionsAt(t, r, kin[0]); got != 1 {
			t.Fatalf("the decision reached its kin %d times; want once, so this checks nothing", got)
		}
		lapsed := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"decision_occurrence"`).
			Set(`"state" = ?`, triage.LapsedState).Set(`"live_key" = ?`, nil).Set(`"ended_at" = ?`, lapsed).
			Where(`"decision_id" = ?`, decided.DecisionID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		// The leak is also on a release still in support, and its kin only on
		// the one past its end of life.
		alsoOnV1(t, r, occurrence)
		endMaster(t, r)

		listed := toReaffirm(t, r, "internal-triager")
		if len(listed) != 1 || listed[0].Decision.ID != decided.DecisionID || listed[0].Occurrences != 1 {
			t.Fatalf("listed to re-affirm: %+v; want decision %d at its one occurrence still in support",
				listed, decided.DecisionID)
		}
		// Every decision listed, as selecting all of them sends it.
		decisions := make([]string, 0, len(listed))
		for _, item := range listed {
			decisions = append(decisions, fmt.Sprint(item.Decision.ID))
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, "/v1/reaffirmations",
			fmt.Sprintf(`{"decisions":[%s],"reasoning":"still checked by the caller"}`, strings.Join(decisions, ","))); got.Code != http.StatusCreated {
			t.Fatalf("re-affirming every decision listed answered %d: %s", got.Code, got.Body)
		}
		if got := decisionsAt(t, r, occurrence); got != 2 {
			t.Errorf("the code finding still in support holds %d rows; want the lapsed one and its re-making", got)
		}
		if got := decisionsAt(t, r, kin[0]); got != 1 {
			t.Errorf("the kin past its end of life holds %d rows; want the lapsed one alone", got)
		}
	})
}
