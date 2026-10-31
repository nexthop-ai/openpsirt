// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
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
			httpapitest.OtherToolRun("semgrep", "dead-store", "563", "src/r.c", 5, 9))
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
		// Covered by the suppression rule below as well, and the decision
		// still says where it stands.
		approve(at["src/r.c:9"], `{"outcome":"not-security","reasoning":"a store the debugger reads"}`)
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
			analysis.NotSecurity:      {at["src/b.c:30"], at["src/r.c:9"]},
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

// TestADecisionAnswersOnlyTheCodeFindingsOfItsProductAndIssue holds the
// decisions a code finding's state is read from to its own product and its
// own issue, both for a decision that answers it and for one waiting on a
// second person: moved to the other product, or filed under the other code
// finding's issue, either leaves the code finding open and in the queue.
func TestADecisionAnswersOnlyTheCodeFindingsOfItsProductAndIssue(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		leak := httpapitest.SeededCodeFinding(t, r)
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-50*time.Minute),
			httpapitest.OtherToolRun("cppcheck", "overflow", "787", "src/b.c", 20))
		var overflow string
		for _, item := range codeFindingsOf(t, r, "security-testing-reader", "").Items {
			if item.Path == "src/b.c" {
				overflow = item.Occurrence
			}
		}
		if overflow == "" {
			t.Fatal("cppcheck's overflow is not in the queue")
		}
		answered := decideCodeFinding(t, r, leak, `{"outcome":"confirmed","reasoning":"the pointer is never freed"}`)
		// A dismissal waits for a second person.
		waits := decideCodeFinding(t, r, overflow, `{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked first"}`)

		theirs, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		decisions := []int64{answered.DecisionID, waits.DecisionID}
		type filedAs struct {
			Product       int64 `bun:"product_id"`
			Vulnerability int64 `bun:"vulnerability_id"`
		}
		filed := make([]filedAs, len(decisions))
		for i, decision := range decisions {
			if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence"`).
				ColumnExpr(`"product_id", "vulnerability_id"`).
				Where(`"decision_id" = ?`, decision).Scan(ctx, &filed[i]); err != nil {
				t.Fatal(err)
			}
		}
		if filed[0].Vulnerability == filed[1].Vulnerability {
			t.Fatal("the two decisions are filed under one issue, so swapping them files neither elsewhere")
		}
		set := func(column string, to func(i int) int64) {
			t.Helper()
			for i, decision := range decisions {
				if _, err := r.DB.DB.NewUpdate().TableExpr(`"decision_occurrence"`).
					Set(`? = ?`, bun.Ident(column), to(i)).Where(`"decision_id" = ?`, decision).Exec(ctx); err != nil {
					t.Fatal(err)
				}
			}
		}
		// The reader reads both products, so the queue across products holds
		// each product's decisions beside the other's code findings.
		reader, err := r.Rights.ByIdentity(ctx, "security-testing-reader")
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Rights.GrantRole(ctx, reader.ID, theirs.ID, access.SecurityTestingRead); err != nil {
			t.Fatal(err)
		}
		read := func(path string) []string {
			var got codeFindingsListed
			httpapitest.Read(t, r, "security-testing-reader", path, &got)
			var out []string
			for _, item := range got.Items {
				out = append(out, item.Occurrence)
			}
			slices.Sort(out)
			return out
		}
		listed := func(query string) []string { return read("/v1/products/mine/code-findings" + query) }
		across := func(query string) []string { return read("/v1/code-findings" + query) }
		both := []string{leak, overflow}
		slices.Sort(both)

		if got := listed(""); len(got) != 0 {
			t.Fatalf("the queue holds %v with one code finding confirmed and the other waiting; want none", got)
		}
		if got := listed("?state=open"); len(got) != 1 || got[0] != overflow {
			t.Fatalf("the open list is %v; want the overflow waiting, open, and not the confirmed leak", got)
		}
		for _, move := range []struct {
			what, column string
			to, at       func(i int) int64
		}{
			{"moved to the other product", "product_id",
				func(int) int64 { return theirs.ID }, func(i int) int64 { return filed[i].Product }},
			{"filed under the other's issue", "vulnerability_id",
				func(i int) int64 { return filed[1-i].Vulnerability }, func(i int) int64 { return filed[i].Vulnerability }},
		} {
			set(move.column, move.to)
			if got := listed(""); !slices.Equal(got, both) {
				t.Errorf("with the decisions %s, the queue is %v; want both code findings, %v", move.what, got, both)
			}
			if got := listed("?state=open"); !slices.Equal(got, both) {
				t.Errorf("with the decisions %s, the open list is %v; want both code findings, %v", move.what, got, both)
			}
			if got := across(""); !slices.Equal(got, both) {
				t.Errorf("with the decisions %s, the queue across products is %v; want both code findings, %v", move.what, got, both)
			}
			if got := across("?state=open"); !slices.Equal(got, both) {
				t.Errorf("with the decisions %s, the open list across products is %v; want both code findings, %v", move.what, got, both)
			}
			set(move.column, move.at)
		}
		if got := listed(""); len(got) != 0 {
			t.Errorf("the queue holds %v once the decisions are back; want none", got)
		}
	})
}
