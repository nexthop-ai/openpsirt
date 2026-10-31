// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// TestEachStateListsTheCodeFindingsStandingInIt holds every list by state to
// the state each of its rows is read in, and to the count of that state: a
// list keeps its state by the conditions that make it, and the count and each
// row work the state out.
func TestEachStateListsTheCodeFindingsStandingInIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		leak, _ := httpapitest.RecordedCodeFinding(t, r, false)
		now := time.Now().UTC()
		// cppcheck's overflows, the second run no longer seeing two of them,
		// and semgrep's dead store under a suppression rule.
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", now.Add(-70*time.Minute),
			httpapitest.OtherToolRun("cppcheck", "overflow", "787", "src/b.c", 20, 30, 40, 50, 70, 80, 90))
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", now.Add(-50*time.Minute),
			httpapitest.OtherToolRun("cppcheck", "overflow", "787", "src/b.c", 20, 30, 40, 50, 90))
		httpapitest.ApplyRunIn(t, r, "semgrep/default", now.Add(-40*time.Minute),
			httpapitest.OtherToolRun("semgrep", "dead-store", "563", "src/r.c", 5))
		at := map[string]string{}
		var rows []struct {
			Occurrence string `bun:"occurrence_identity"`
			Path       string `bun:"path"`
			Line       int    `bun:"start_line"`
		}
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
			ColumnExpr(`"f"."occurrence_identity", "ar"."path", "ar"."start_line"`).Scan(t.Context(), &rows); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			at[fmt.Sprintf("%s:%d", row.Path, row.Line)] = row.Occurrence
		}
		decideCodeFinding(t, r, at["src/b.c:20"], `{"outcome":"confirmed","reasoning":"the length is attacker controlled"}`)
		approve := func(occurrence, body string) {
			decided := decideCodeFinding(t, r, occurrence, body)
			if got := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
				fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`); got.Code != http.StatusOK {
				t.Fatalf("approving the decision answered %d: %s", got.Code, got.Body)
			}
		}
		approve(at["src/b.c:30"], `{"outcome":"not-security","reasoning":"a crash in a tool that exits"}`)
		approve(at["src/b.c:40"], `{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked first"}`)
		// Waiting for a second person, so open and out of the queue.
		decideCodeFinding(t, r, at["src/b.c:50"], `{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked first"}`)
		codeFinding := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + at["src/b.c:70"]
		if got := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, codeFinding+"/fixed",
			httpapitest.FixedBody(t, r, codeFinding, "the bounds check landed")); got.Code != http.StatusOK {
			t.Fatalf("closing the overflow answered %d: %s", got.Code, got.Body)
		}
		rule := proposeSuppressionRule(t, r, `{"rule":"semgrep/dead-store","prefix":"src/r.c",`+
			`"reason":"false_positive","reasoning":"the store is read by the debugger"}`)
		approveSuppressionRule(t, r, rule.ID)

		want := map[analysis.State][]string{
			analysis.RecordedAsFlaw:   {leak},
			analysis.Confirmed:        {at["src/b.c:20"]},
			analysis.NotSecurity:      {at["src/b.c:30"]},
			analysis.Dismissed:        {at["src/b.c:40"], at["src/r.c:5"]},
			analysis.Open:             {at["src/b.c:50"], at["src/b.c:90"]},
			analysis.Fixed:            {at["src/b.c:70"]},
			analysis.NoLongerDetected: {at["src/b.c:80"]},
		}
		for _, state := range analysis.States() {
			got := codeFindingsOf(t, r, "security-testing-reader", "?state="+string(state))
			var listed []string
			for _, item := range got.Items {
				listed = append(listed, item.Occurrence)
				if item.State != string(state) {
					t.Errorf("the %s list holds %s read as %s", state, item.Occurrence, item.State)
				}
			}
			slices.Sort(listed)
			wanted := slices.Clone(want[state])
			slices.Sort(wanted)
			if !slices.Equal(listed, wanted) || got.Total != len(wanted) || got.States[string(state)] != len(wanted) {
				t.Errorf("the %s list is %v, %d in all and counted %d; want %v", state, listed, got.Total,
					got.States[string(state)], wanted)
			}
		}
		if got := codeFindingsOf(t, r, "security-testing-reader", ""); len(got.Items) != 1 ||
			got.Items[0].Occurrence != at["src/b.c:90"] || got.Waiting != 1 || got.Ruled != 1 {
			t.Errorf("the queue is %+v; want the one open code finding no decision waits on", got)
		}
	})
}
