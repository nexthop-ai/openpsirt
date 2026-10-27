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

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const codeFindingDecisionAt = "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/%s/decision"

func TestADismissedCodeFindingStatesAReasonAndWaitsForASecondPerson(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(codeFindingDecisionAt, httpapitest.SeededCodeFinding(t, r))
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at,
			`{"outcome":"dismissed","reasoning":"never reached"}`); got.Code != http.StatusUnprocessableEntity {
			t.Fatalf("a dismissal with no reason answered %d: %s", got.Code, got.Body)
		}
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the dismissal answered %d: %s", got.Code, got.Body)
		}
		var decided core.DecisionOccurrenceBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		if !decided.NeedsApproval || decided.Reason != "false_positive" || decided.Justification != "" {
			t.Fatalf("recorded %+v; want a reason, waiting for a second person", decided)
		}
		approval := fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID)
		// Agreeing to internal material takes reading it as well as the
		// right to agree.
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost, approval, `{}`); got.Code != http.StatusNotFound {
			t.Errorf("an approver who reads no internal material answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost, approval, `{}`); got.Code != http.StatusOK {
			t.Errorf("the internal reviewer's approval answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestADecisionAboutACodeFindingIsAgreedToOnlyByAnApprover(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(codeFindingDecisionAt, httpapitest.SeededCodeFinding(t, r))
		got := httpapitest.AsPerson(t, r, "internal-code-finding", http.MethodPost, at,
			`{"outcome":"dismissed","reason":"wont_fix","reasoning":"a tool that exits"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the dismissal answered %d: %s", got.Code, got.Body)
		}
		var decided core.DecisionOccurrenceBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		// The decision says it is internal, which is what a screen offering
		// Agree asks the reader's reach at.
		var decision struct {
			Internal bool `json:"internal"`
		}
		httpapitest.Read(t, r, "internal-reviewer", fmt.Sprintf("/v1/decisions/%d", decided.DecisionID), &decision)
		if !decision.Internal {
			t.Error("a decision about a code finding does not say it is internal")
		}
		approval := fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID)
		// Triaging internal material is not the right to agree to it.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, approval, `{}`),
			http.StatusNotFound)
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost, approval, `{}`); got.Code != http.StatusOK {
			t.Errorf("the internal reviewer's approval answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestAConfirmedCodeFindingWaitsForNobody(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(codeFindingDecisionAt, httpapitest.SeededCodeFinding(t, r))
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at,
			`{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the confirmation answered %d: %s", got.Code, got.Body)
		}
		var decided core.DecisionOccurrenceBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		if decided.NeedsApproval {
			t.Error("a confirmed code finding waits for a second person")
		}
	})
}

func TestACodeFindingIsJudgedOnlyByThoseWhoTriageInternalMaterial(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(codeFindingDecisionAt, httpapitest.SeededCodeFinding(t, r))
		body := `{"outcome":"confirmed","reasoning":"real"}`
		// Somebody triaging the other visibilities finds no code finding there, and
		// somebody reading internal material is answered the same way.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at, body), http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodPost, at, body), http.StatusNotFound)
	})
}

func TestAVulnerabilityOutcomeIsRefusedOnALead(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(codeFindingDecisionAt, httpapitest.SeededCodeFinding(t, r))
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at,
			`{"outcome":"not-applicable","reasoning":"absent"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a vulnerability outcome on a code finding answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestACodeFindingOutcomeIsRefusedOnAVulnerability(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := r.Scanned(t)
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/findings/CVE-2026-9999/occurrences/" + occurrence + "/decision"
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"confirmed","reasoning":"real"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a code finding outcome on a vulnerability answered %d: %s", got.Code, got.Body)
		}
	})
}

// codeFindingState is where the seeded code finding stands, as its evidence says.
func codeFindingState(t *testing.T, r *httpapitest.Reach, occurrence string) string {
	t.Helper()
	var got struct {
		State string `json:"state"`
	}
	httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence, &got)
	return got.State
}

func TestACodeFindingStandsWhereTheDecisionAgreedToPutsIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		if got := codeFindingState(t, r, occurrence); got != "open" {
			t.Fatalf("a code finding in the series' first run is %q; want open", got)
		}
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(codeFindingDecisionAt, occurrence),
			`{"outcome":"dismissed","reason":"used_in_tests","reasoning":"only the test harness calls it"}`)
		var decided core.DecisionOccurrenceBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		if got := codeFindingState(t, r, occurrence); got != "open" {
			t.Errorf("a code finding whose dismissal waits for a second person is %q; want it open", got)
		}
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`)
		if got := codeFindingState(t, r, occurrence); got != "dismissed" {
			t.Errorf("a code finding whose dismissal was agreed to is %q; want dismissed", got)
		}
	})
}

func TestACodeFindingIsFixedOnlyOnceARunNoLongerSeesIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		codeFinding := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
		at := codeFinding + "/fixed"
		body := httpapitest.FixedBody(t, r, codeFinding, "the bounds check landed")
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at, body),
			http.StatusConflict)

		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRun(false))
		body = httpapitest.FixedBody(t, r, codeFinding, "the bounds check landed")
		if got := codeFindingState(t, r, occurrence); got != "no-longer-detected" {
			t.Fatalf("a code finding the newest run did not see is %q; want no-longer-detected", got)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodPost, at, body),
			http.StatusNotFound)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at, body); got.Code != http.StatusOK {
			t.Fatalf("closing a code finding nobody sees answered %d: %s", got.Code, got.Body)
		}
		if got := codeFindingState(t, r, occurrence); got != "fixed" {
			t.Errorf("a code finding closed as fixed is %q; want fixed", got)
		}
		if got := codeFindingsOf(t, r, "internal-reader", "?state=fixed"); len(got.Items) != 1 ||
			got.Items[0].Occurrence != occurrence || got.States["fixed"] != 1 {
			t.Errorf("the fixed code findings are %+v; want the one closed, listed and counted", got)
		}

		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-30*time.Minute), httpapitest.CodeFindingRun(true))
		if got := codeFindingState(t, r, occurrence); got == "fixed" {
			t.Error("a fixed code finding seen again is still fixed")
		}
		if got := codeFindingsOf(t, r, "internal-reader", "?state=fixed"); len(got.Items) != 0 || got.States["fixed"] != 0 {
			t.Errorf("the fixed code findings are %+v; want none once the code finding opened anew", got)
		}

		// Fixed a second time on the one build, it is listed on one build.
		httpapitest.ApplyRun(t, r, time.Now().UTC(), httpapitest.CodeFindingRun(false))
		body = httpapitest.FixedBody(t, r, codeFinding, "the bounds check landed")
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at, body); got.Code != http.StatusOK {
			t.Fatalf("closing the code finding again answered %d: %s", got.Code, got.Body)
		}
		if got := codeFindingsOf(t, r, "internal-reader", "?state=fixed"); len(got.Items) != 1 || got.Items[0].Builds != 1 {
			t.Errorf("the fixed code findings are %+v; want the one code finding on its one build", got)
		}
	})
}

func TestAFixedCodeFindingNamesARunOfItsBuildThatDidNotSeeIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		codeFinding := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
		var saw int64
		if err := r.DB.DB.NewSelect().TableExpr(`"series_run" AS "sr"`).ColumnExpr(`MIN("sr"."id")`).
			Scan(t.Context(), &saw); err != nil {
			t.Fatal(err)
		}
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRun(false))
		// The run that saw it is not the build that fixed it.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFinding+"/fixed",
			fmt.Sprintf(`{"because":"the bounds check landed","fixed_in":%d}`, saw)), http.StatusUnprocessableEntity)
		var evidence struct {
			NotSeenRun int64 `json:"not_seen_run"`
			FixedIn    *struct {
				Run int64 `json:"run"`
			} `json:"fixed_in"`
		}
		httpapitest.Read(t, r, "internal-reader", codeFinding, &evidence)
		if evidence.NotSeenRun == 0 || evidence.FixedIn != nil {
			t.Fatalf("a code finding no longer detected reads %+v; want the run that did not see it, and no fix", evidence)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFinding+"/fixed",
			fmt.Sprintf(`{"because":"the bounds check landed","fixed_in":%d}`, evidence.NotSeenRun)); got.Code != http.StatusOK {
			t.Fatalf("closing the code finding answered %d: %s", got.Code, got.Body)
		}
		httpapitest.Read(t, r, "internal-reader", codeFinding, &evidence)
		if evidence.FixedIn == nil || evidence.FixedIn.Run != evidence.NotSeenRun {
			t.Errorf("a code finding closed as fixed names %+v as the build that fixed it; want run %d",
				evidence.FixedIn, evidence.NotSeenRun)
		}
	})
}

func TestADismissalLapsesWhereItsCodeFindingIsPairedOnlyProbably(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(codeFindingDecisionAt, occurrence),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"freed by the caller"}`)
		var decided core.DecisionOccurrenceBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`)

		// The same line again pairs on the whole key, and the dismissal stands.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRunAt(12))
		if got := codeFindingState(t, r, occurrence); got != "dismissed" {
			t.Fatalf("a dismissed code finding seen again on its whole key is %q; want dismissed", got)
		}
		// Two lines down pairs it on its nearest line.
		httpapitest.ApplyRun(t, r, time.Now().UTC(), httpapitest.CodeFindingRunAt(14))
		if got := codeFindingState(t, r, occurrence); got == "dismissed" {
			t.Fatalf("a dismissed code finding paired only on its nearest line is still dismissed")
		}
		// Re-affirmed by its author, it stands again on the agreement it had.
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/reaffirmation", decided.DecisionID),
			`{"reasoning":"still freed by the caller after the move"}`); got.Code != http.StatusCreated {
			t.Fatalf("re-affirming answered %d: %s", got.Code, got.Body)
		}
		if got := codeFindingState(t, r, occurrence); got != "dismissed" {
			t.Errorf("a re-affirmed dismissal leaves the code finding %q; want dismissed", got)
		}
	})
}

func TestAConfirmationStandsWhereItsCodeFindingIsPairedOnlyProbably(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRunAt(12))
		// Two lines down pairs it on its nearest line.
		httpapitest.ApplyRun(t, r, time.Now().UTC(), httpapitest.CodeFindingRunAt(14))
		if got := codeFindingState(t, r, occurrence); got != "confirmed" {
			t.Errorf("a confirmed code finding paired only on its nearest line is %q; want it confirmed still", got)
		}
	})
}

// codeFindingsListed is a product's list of code findings as somebody reads it.
type codeFindingsListed struct {
	Items []struct {
		Occurrence string `json:"occurrence"`
		Rule       string `json:"rule"`
		Path       string `json:"path"`
		State      string `json:"state"`
		Builds     int    `json:"builds"`
	} `json:"items"`
	Total   int            `json:"total"`
	States  map[string]int `json:"states"`
	Waiting int            `json:"waiting"`
	Ruled   int            `json:"ruled"`
	Ended   int            `json:"past_end_of_life"`
}

func codeFindingsOf(t *testing.T, r *httpapitest.Reach, who, query string) codeFindingsListed {
	t.Helper()
	var got codeFindingsListed
	httpapitest.Read(t, r, who, "/v1/products/mine/code-findings"+query, &got)
	return got
}

func TestTheQueueHoldsACodeFindingFromTheSeriesFirstRun(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		got := codeFindingsOf(t, r, "internal-reader", "")
		if len(got.Items) != 1 || got.Total != 1 || got.Items[0].Occurrence != occurrence || got.Items[0].State != "open" ||
			got.Items[0].Path != "src/a.c" || got.Items[0].Builds != 1 || got.States["open"] != 1 {
			t.Fatalf("the queue is %+v; want the seeded code finding listed and counted open", got)
		}
		// Somebody who reads no internal material is told of no code finding.
		if got := codeFindingsOf(t, r, "reader", ""); len(got.Items) != 0 || len(got.States) != 0 {
			t.Errorf("a reader of public material is shown %+v", got)
		}
	})
}

func TestADecisionWaitingOnASecondPersonTakesItsCodeFindingOutOfTheQueue(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(codeFindingDecisionAt, occurrence),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"checked a line above"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the dismissal answered %d: %s", got.Code, got.Body)
		}
		queue := codeFindingsOf(t, r, "internal-reader", "")
		if len(queue.Items) != 0 || queue.Waiting != 1 || queue.States["open"] != 1 {
			t.Fatalf("the queue is %+v; want the code finding left out and counted as waiting", queue)
		}
		if listed := codeFindingsOf(t, r, "internal-reader", "?state=open"); len(listed.Items) != 1 {
			t.Errorf("the open code findings are %+v; want the one waiting", listed.Items)
		}
	})
}

func TestACodeFindingsEvidenceNamesItsRuleAndTheDecisionStandingAtIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		type evidence struct {
			Rule               string                       `json:"rule"`
			DecisionOccurrence *core.DecisionOccurrenceBody `json:"decision_occurrence"`
		}
		var before evidence
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence, &before)
		if before.Rule != "clang-tidy/leak" || before.DecisionOccurrence != nil {
			t.Fatalf("the evidence before any decision is %+v; want the rule and no decision", before)
		}
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(codeFindingDecisionAt, occurrence),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"checked a line above"}`)
		var decided core.DecisionOccurrenceBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		var after evidence
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence, &after)
		if after.DecisionOccurrence == nil || after.DecisionOccurrence.DecisionID != decided.DecisionID || !after.DecisionOccurrence.NeedsApproval {
			t.Errorf("the evidence names the decision %+v; want decision %d, waiting", after.DecisionOccurrence, decided.DecisionID)
		}
		// A decision withdrawn stands nowhere.
		httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, fmt.Sprintf("/v1/decisions/%d", decided.DecisionID), ``)
		var withdrawn evidence
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence, &withdrawn)
		if withdrawn.DecisionOccurrence != nil {
			t.Errorf("the evidence names a withdrawn decision %+v", withdrawn.DecisionOccurrence)
		}
	})
}

func TestTheAuditLogStatesACodeFindingsReasonAsAReason(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decided := decideCodeFinding(t, r, occurrence,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`)
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`)
		var record struct {
			Items []struct {
				Outcome       string `json:"outcome"`
				Justification string `json:"justification"`
				Reason        string `json:"reason"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "internal-reviewer", "/v1/audit?outcome=dismissed", &record)
		if len(record.Items) != 1 {
			t.Fatalf("the record holds %+v; want the one dismissal", record.Items)
		}
		if got := record.Items[0]; got.Reason != "false_positive" || got.Justification != "" {
			t.Errorf("the record states %+v; want the code finding's reason as its reason and no justification", got)
		}
	})
}

func TestACodeFindingSeenOnlyInReleasesPastTheirEndOfLifeLeavesTheQueueAndIsKeptAsItStands(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		ended := func(on *time.Time) {
			t.Helper()
			if _, err := r.DB.DB.NewUpdate().TableExpr(`"branch_or_tag"`).Set(`"eol_on" = ?`, on).
				Where(`"name" = ?`, "master").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		yesterday := time.Now().UTC().Add(-48 * time.Hour).Truncate(24 * time.Hour)
		ended(&yesterday)

		if got := codeFindingsOf(t, r, "internal-reader", ""); len(got.Items) != 0 || got.Ended != 1 {
			t.Errorf("the queue is %+v; want the code finding left out and counted", got)
		}
		if got := codeFindingsOf(t, r, "internal-reader", "?state=open"); len(got.Items) != 1 {
			t.Errorf("the open code findings are %+v; want the code finding still listed", got)
		}
		var evidence struct {
			Ended bool `json:"past_end_of_life"`
		}
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence, &evidence)
		if !evidence.Ended {
			t.Error("the code finding's evidence does not say its releases are past their end of life")
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"+occurrence+"/decision",
			`{"outcome":"confirmed","reasoning":"p leaks"}`), http.StatusConflict)

		ended(nil)
		if got := codeFindingsOf(t, r, "internal-reader", ""); len(got.Items) != 1 || got.Ended != 0 {
			t.Errorf("back in support, the queue is %+v; want the code finding", got)
		}
	})
}

func TestWithdrawingAnAgreedDismissalOfACodeFindingReopensIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(codeFindingDecisionAt, occurrence),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the dismissal answered %d: %s", got.Code, got.Body)
		}
		var decided core.DecisionOccurrenceBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		decision := fmt.Sprintf("/v1/decisions/%d", decided.DecisionID)
		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost, decision+"/approval", `{}`); got.Code != http.StatusOK {
			t.Fatalf("the approval answered %d: %s", got.Code, got.Body)
		}
		if got := codeFindingState(t, r, occurrence); got != "dismissed" {
			t.Fatalf("a code finding whose dismissal was agreed to is %q; want dismissed", got)
		}
		if queued := codeFindingsOf(t, r, "internal-reader", ""); len(queued.Items) != 0 {
			t.Fatalf("the queue holds %+v beside an agreed dismissal; want nothing", queued.Items)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete, decision, ``); got.Code != http.StatusNoContent {
			t.Fatalf("withdrawing the decision answered %d: %s", got.Code, got.Body)
		}
		if got := codeFindingState(t, r, occurrence); got != "open" {
			t.Errorf("a code finding whose dismissal was withdrawn is %q; want open", got)
		}
		if queued := codeFindingsOf(t, r, "internal-reader", ""); len(queued.Items) != 1 || queued.Items[0].Occurrence != occurrence {
			t.Errorf("the queue holds %+v after the dismissal was withdrawn; want the code finding back", queued.Items)
		}
	})
}

// A run of the code finding's own series on its own build, applied and comparable, is
// the only run a fix is named by: each of those taken away from a run that
// would otherwise be accepted is refused.
func TestAFixedCodeFindingNamesOnlyAnAppliedComparableRunOfItsSeriesOnItsBuild(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		codeFinding := "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
		now := time.Now().UTC()
		httpapitest.ApplyRun(t, r, now.Add(-2*time.Hour), httpapitest.CodeFindingRun(false))
		httpapitest.ApplyRun(t, r, now.Add(-time.Hour), httpapitest.CodeFindingRun(false))
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", now.Add(-90*time.Minute),
			httpapitest.OtherToolRun("cppcheck", "overflow", "787", "src/c.c", 9))
		var later struct {
			ID     int64 `bun:"id"`
			Series int64 `bun:"series_id"`
			Build  int64 `bun:"build_id"`
		}
		if err := r.DB.DB.NewSelect().TableExpr(`"series_run" AS "sr"`).
			ColumnExpr(`"sr"."id", "sr"."series_id", "sr"."build_id"`).
			Where(`"sr"."built_at" = (SELECT MAX("m"."built_at") FROM "series_run" AS "m" WHERE "m"."series_id" =
				(SELECT "s0"."series_id" FROM "series_run" AS "s0" ORDER BY "s0"."id" LIMIT 1))`).
			Where(`"sr"."series_id" = (SELECT "s1"."series_id" FROM "series_run" AS "s1" ORDER BY "s1"."id" LIMIT 1)`).
			Scan(t.Context(), &later); err != nil {
			t.Fatal(err)
		}
		var otherSeries int64
		if err := r.DB.DB.NewSelect().TableExpr(`"series_run" AS "sr"`).ColumnExpr(`MAX("sr"."series_id")`).
			Where(`"sr"."series_id" <> ?`, later.Series).Scan(t.Context(), &otherSeries); err != nil {
			t.Fatal(err)
		}
		names := catalog.NewStore(r.DB.DB)
		mine, err := names.ProductByName(t.Context(), "mine")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := names.DeclareBranchOrTag(t.Context(), mine.ID, "v1", catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
		otherBuild := r.BuildOf(t, httpapitest.Build{Product: "mine", BranchOrTag: "v1", Variant: "broadcom"})
		body := fmt.Sprintf(`{"because":"the bounds check landed","fixed_in":%d}`, later.ID)
		for _, c := range []struct {
			name   string
			column string
			value  any
			was    any
		}{
			{"on another build", "build_id", otherBuild, later.Build},
			{"of another series", "series_id", otherSeries, later.Series},
			{"not comparable", "comparable", false, true},
			{"not applied", "status", "superseded", "applied"},
		} {
			if _, err := r.DB.DB.NewUpdate().TableExpr(`"series_run"`).Set(`"`+c.column+`" = ?`, c.value).
				Where(`"id" = ?`, later.ID).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
			if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFinding+"/fixed", body); got.Code != http.StatusUnprocessableEntity {
				t.Errorf("naming a run %s answered %d: %s", c.name, got.Code, got.Body)
			}
			if _, err := r.DB.DB.NewUpdate().TableExpr(`"series_run"`).Set(`"`+c.column+`" = ?`, c.was).
				Where(`"id" = ?`, later.ID).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFinding+"/fixed", body); got.Code != http.StatusOK {
			t.Errorf("naming the later run of the code finding's series on its build answered %d: %s", got.Code, got.Body)
		}
	})
}

// Static analysis is the one testing method recorded, so narrowing to it keeps
// every code finding, and a method nothing records is refused by name.
func TestTheQueueNarrowsByTheMethodThatReportedACodeFinding(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		got := codeFindingsOf(t, r, "internal-reader", "?method=sast")
		if got.Total != 1 || len(got.Items) != 1 || got.Items[0].Occurrence != occurrence {
			t.Fatalf("the static analysis queue is %+v; want the seeded code finding", got)
		}
		refused := httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet,
			"/v1/products/mine/code-findings?method=dast", "")
		if refused.Code != http.StatusUnprocessableEntity || !strings.Contains(refused.Body.String(), "method") {
			t.Errorf("a method nothing records answered %d: %s", refused.Code, refused.Body)
		}
	})
}
