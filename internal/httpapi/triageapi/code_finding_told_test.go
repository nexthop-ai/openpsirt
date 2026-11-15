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

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// toldOfKind is how many lines of one kind a person reads.
func toldOfKind(t *testing.T, r *httpapitest.Reach, who string, kind notify.Kind) int {
	t.Helper()
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

func TestRowsOfACodeFindingDecisionSetAsideAreToldToAProposerWhoReadsOnlySecurityTestingWork(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		decided := decideCodeFinding(t, r, occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked by the caller"}`)
		var aside int64
		if err := r.DB.DB.NewSelect().Table("decision_occurrence").Column("id").
			Where(`"occurrence_identity" = ?`, kin[0]).Where(`"decision_id" = ?`, decided.DecisionID).
			Scan(t.Context(), &aside); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID),
			fmt.Sprintf(`{"except":[%d],"because":"the overflow is not the leak"}`, aside)); got.Code != http.StatusOK {
			t.Fatalf("approving with a row set aside answered %d: %s", got.Code, got.Body)
		}
		if n := toldOfKind(t, r, "security-testing-triager", notify.SentBack); n != 1 {
			t.Errorf("the proposer, who reads security testing work alone, read %d lines about the rows set aside; want one", n)
		}
	})
}

func TestAMentionOnACodeFindingDecisionReachesSomebodyWhoReadsOnlySecurityTestingWork(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		decided := decideCodeFinding(t, r, httpapitest.SeededCodeFinding(t, r),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`)
		if got := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/comments", decided.DecisionID),
			`{"body":"@security-testing-reader, could you look at the check above?"}`); got.Code >= 400 {
			t.Fatalf("commenting answered %d: %s", got.Code, got.Body)
		}
		if n := toldOfKind(t, r, "security-testing-reader", notify.Mentioned); n != 1 {
			t.Errorf("somebody who reads security testing work alone read %d mentions; want one", n)
		}
	})
}

func TestAnApprovalBatchUndoneIsToldToACodeFindingProposerWhoReadsOnlySecurityTestingWork(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		decided := decideCodeFinding(t, r, httpapitest.SeededCodeFinding(t, r),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`)
		if got := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{"batch":"tuesday"}`); got.Code != http.StatusOK {
			t.Fatalf("approving under a batch answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodDelete,
			"/v1/approval-batches/tuesday", ""); got.Code != http.StatusOK {
			t.Fatalf("undoing the batch answered %d: %s", got.Code, got.Body)
		}
		if n := toldOfKind(t, r, "security-testing-triager", notify.ApprovalUndone); n != 1 {
			t.Errorf("the proposer, who reads security testing work alone, read %d lines about the batch undone; want one", n)
		}
	})
}

func TestAnApprovalBatchUndoneOverAFlawConfirmationUndoesAndTellsOnlyTheOtherDecision(t *testing.T) {
	// One batch agreed to a confirmation a flaw record now rests on and to
	// a dismissal of another code finding. Undoing it leaves the
	// confirmation standing, puts the dismissal back in the queue, and
	// tells the dismissal's proposer alone.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		occurrence := httpapitest.SeededCodeFinding(t, r)
		confirmed := decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"p leaks on the early return"}`)
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.OtherToolRun("cppcheck", "overflow", "120", "src/c.c", 4))
		var other string
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."occurrence_identity"`).
			Where(`"f"."kind" = ?`, kind.Analysis).Where(`"f"."occurrence_identity" <> ?`, occurrence).
			Scan(ctx, &other); err != nil {
			t.Fatal(err)
		}
		got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, fmt.Sprintf(codeFindingDecisionAt, other),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"n is bounded by the caller"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("dismissing the second code finding answered %d: %s", got.Code, got.Body)
		}
		var dismissed struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &dismissed); err != nil {
			t.Fatal(err)
		}
		for _, decision := range []int64{confirmed.DecisionID, dismissed.DecisionID} {
			if got := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
				fmt.Sprintf("/v1/decisions/%d/approval", decision), `{"batch":"tuesday"}`); got.Code != http.StatusOK {
				t.Fatalf("agreeing to decision %d answered %d: %s", decision, got.Code, got.Body)
			}
		}
		flawAt := strings.TrimSuffix(fmt.Sprintf(codeFindingDecisionAt, occurrence), "/decision") + "/flaw"
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, flawAt,
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the flaw record answered %d: %s", got.Code, got.Body)
		}

		got = httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodDelete, "/v1/approval-batches/tuesday", "")
		if got.Code != http.StatusOK {
			t.Fatalf("undoing the batch answered %d: %s", got.Code, got.Body)
		}
		var undone struct {
			Undone int64 `json:"undone"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &undone); err != nil {
			t.Fatal(err)
		}
		states := func(decision int64) []string {
			t.Helper()
			var held []string
			if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."state"`).
				Where(`"de"."decision_id" = ?`, decision).Scan(ctx, &held); err != nil {
				t.Fatal(err)
			}
			return held
		}
		if held := states(confirmed.DecisionID); len(held) != 1 || held[0] != "approved" {
			t.Errorf("the confirmation the flaw rests on is %v; want it approved still", held)
		}
		back := states(dismissed.DecisionID)
		if len(back) == 0 || int64(len(back)) != undone.Undone {
			t.Errorf("undoing the batch undid %d rows; want the dismissal's %d", undone.Undone, len(back))
		}
		for _, state := range back {
			if state != "proposed" {
				t.Errorf("a row of the dismissal is %s; want it back in the queue", state)
			}
		}
		if n := toldOfKind(t, r, "code-finding-handler", notify.ApprovalUndone); n != 1 {
			t.Errorf("the dismissal's proposer read %d lines about the batch undone; want one", n)
		}
		if n := toldOfKind(t, r, "security-testing-triager", notify.ApprovalUndone); n != 0 {
			t.Errorf("the confirmation's proposer read %d lines about the batch undone; want none, as it stands", n)
		}
	})
}
