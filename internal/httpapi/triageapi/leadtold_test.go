// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"fmt"
	"net/http"
	"testing"

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

func TestRowsOfALeadDecisionSetAsideAreToldToAProposerWhoReadsOnlyInternalWork(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, kin := besideTheLeak(t, r, 4)
		decided := decideLead(t, r, occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked by the caller"}`)
		var aside int64
		if err := r.DB.DB.NewSelect().Table("decision_occurrence").Column("id").
			Where(`"occurrence_identity" = ?`, kin[0]).Where(`"decision_id" = ?`, decided.DecisionID).
			Scan(t.Context(), &aside); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID),
			fmt.Sprintf(`{"except":[%d],"because":"the overflow is not the leak"}`, aside)); got.Code != http.StatusOK {
			t.Fatalf("approving with a row set aside answered %d: %s", got.Code, got.Body)
		}
		if n := toldOfKind(t, r, "internal-triager", notify.SentBack); n != 1 {
			t.Errorf("the proposer, who reads internal work alone, read %d lines about the rows set aside; want one", n)
		}
	})
}

func TestAMentionOnALeadDecisionReachesSomebodyWhoReadsOnlyInternalWork(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		decided := decideLead(t, r, httpapitest.SeededLead(t, r),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/comments", decided.DecisionID),
			`{"body":"@internal-reader, could you look at the check above?"}`); got.Code >= 400 {
			t.Fatalf("commenting answered %d: %s", got.Code, got.Body)
		}
		if n := toldOfKind(t, r, "internal-reader", notify.Mentioned); n != 1 {
			t.Errorf("somebody who reads internal work alone read %d mentions; want one", n)
		}
	})
}

func TestAnApprovalBatchUndoneIsToldToALeadProposerWhoReadsOnlyInternalWork(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		decided := decideLead(t, r, httpapitest.SeededLead(t, r),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`)
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{"batch":"tuesday"}`); got.Code != http.StatusOK {
			t.Fatalf("approving under a batch answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodDelete,
			"/v1/approval-batches/tuesday", ""); got.Code != http.StatusOK {
			t.Fatalf("undoing the batch answered %d: %s", got.Code, got.Body)
		}
		if n := toldOfKind(t, r, "internal-triager", notify.ApprovalUndone); n != 1 {
			t.Errorf("the proposer, who reads internal work alone, read %d lines about the batch undone; want one", n)
		}
	})
}
