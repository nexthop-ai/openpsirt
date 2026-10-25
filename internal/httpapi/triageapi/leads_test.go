// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const leadDecisionAt = "/v1/products/mine/streams/master/variants/broadcom/leads/%s/decision"

func TestADismissedLeadStatesAReasonAndWaitsForASecondPerson(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(leadDecisionAt, httpapitest.SeededLead(t, r))
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at,
			`{"outcome":"dismissed","reasoning":"never reached"}`); got.Code != http.StatusUnprocessableEntity {
			t.Fatalf("a dismissal with no reason answered %d: %s", got.Code, got.Body)
		}
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the pointer is checked a line above"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the dismissal answered %d: %s", got.Code, got.Body)
		}
		var decided core.DecisionBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		if !decided.NeedsApproval || decided.Reason != "false_positive" || decided.Justification != "" {
			t.Fatalf("recorded %+v; want a reason, waiting for a second person", decided)
		}
		approval := fmt.Sprintf("/v1/claims/%d/approval", decided.ClaimID)
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

func TestAConfirmedLeadWaitsForNobody(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(leadDecisionAt, httpapitest.SeededLead(t, r))
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at,
			`{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the confirmation answered %d: %s", got.Code, got.Body)
		}
		var decided core.DecisionBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		if decided.NeedsApproval {
			t.Error("a confirmed lead waits for a second person")
		}
	})
}

func TestALeadIsJudgedOnlyByThoseWhoTriageInternalMaterial(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(leadDecisionAt, httpapitest.SeededLead(t, r))
		body := `{"outcome":"confirmed","reasoning":"real"}`
		// Somebody triaging the other visibilities finds no lead there, and
		// somebody reading internal material is answered the same way.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, at, body), http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodPost, at, body), http.StatusNotFound)
	})
}

func TestAVulnerabilityOutcomeIsRefusedOnALead(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		at := fmt.Sprintf(leadDecisionAt, httpapitest.SeededLead(t, r))
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at,
			`{"outcome":"not-applicable","reasoning":"absent"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a vulnerability outcome on a lead answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestALeadOutcomeIsRefusedOnAVulnerability(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		at := "/v1/products/mine/streams/master/variants/broadcom/findings/CVE-2026-9999/places/" + place + "/decision"
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"confirmed","reasoning":"real"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a lead outcome on a vulnerability answered %d: %s", got.Code, got.Body)
		}
	})
}

// leadState is where the seeded lead stands, as its evidence says.
func leadState(t *testing.T, r *httpapitest.Reach, place string) string {
	t.Helper()
	var got struct {
		State string `json:"state"`
	}
	httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/streams/master/variants/broadcom/leads/"+place, &got)
	return got.State
}

func TestALeadStandsWhereTheClaimAgreedToPutsIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		if got := leadState(t, r, place); got != "baseline" {
			t.Fatalf("a lead in the series' first run is %q; want baseline", got)
		}
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(leadDecisionAt, place),
			`{"outcome":"dismissed","reason":"used_in_tests","reasoning":"only the test harness calls it"}`)
		var decided core.DecisionBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		if got := leadState(t, r, place); got != "baseline" {
			t.Errorf("a lead whose dismissal waits for a second person is %q; want it where it was", got)
		}
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", decided.ClaimID), `{}`)
		if got := leadState(t, r, place); got != "dismissed" {
			t.Errorf("a lead whose dismissal was agreed to is %q; want dismissed", got)
		}
	})
}

func TestALeadIsFixedOnlyOnceARunNoLongerSeesIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		at := "/v1/products/mine/streams/master/variants/broadcom/leads/" + place + "/fixed"
		body := `{"because":"the bounds check landed"}`
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at, body),
			http.StatusConflict)

		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.LeadRun(false))
		if got := leadState(t, r, place); got != "not-reproduced" {
			t.Fatalf("a lead the newest run did not see is %q; want not-reproduced", got)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodPost, at, body),
			http.StatusNotFound)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at, body); got.Code != http.StatusOK {
			t.Fatalf("closing a lead nobody sees answered %d: %s", got.Code, got.Body)
		}
		if got := leadState(t, r, place); got != "fixed" {
			t.Errorf("a lead closed as fixed is %q; want fixed", got)
		}

		httpapitest.ApplyRun(t, r, time.Now().UTC(), httpapitest.LeadRun(true))
		if got := leadState(t, r, place); got == "fixed" {
			t.Error("a fixed lead seen again is still fixed")
		}
	})
}

func TestADismissalLapsesWhereItsLeadIsPairedOnlyProbably(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(leadDecisionAt, place),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"freed by the caller"}`)
		var decided core.DecisionBody
		if err := json.Unmarshal(got.Body.Bytes(), &decided); err != nil {
			t.Fatal(err)
		}
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", decided.ClaimID), `{}`)

		// The same line again pairs on the whole key, and the dismissal stands.
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.LeadRunAt(12))
		if got := leadState(t, r, place); got != "dismissed" {
			t.Fatalf("a dismissed lead seen again on its whole key is %q; want dismissed", got)
		}
		// Two lines down pairs it on its nearest line.
		httpapitest.ApplyRun(t, r, time.Now().UTC(), httpapitest.LeadRunAt(14))
		if got := leadState(t, r, place); got == "dismissed" {
			t.Fatalf("a dismissed lead paired only on its nearest line is still dismissed")
		}
		// Re-affirmed by its author, it stands again on the agreement it had.
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", decided.ClaimID),
			`{"reasoning":"still freed by the caller after the move"}`); got.Code != http.StatusCreated {
			t.Fatalf("re-affirming answered %d: %s", got.Code, got.Body)
		}
		if got := leadState(t, r, place); got != "dismissed" {
			t.Errorf("a re-affirmed dismissal leaves the lead %q; want dismissed", got)
		}
	})
}

// leadsListed is a product's list of leads as somebody reads it.
type leadsListed struct {
	Items []struct {
		Place  string `json:"place"`
		Rule   string `json:"rule"`
		Path   string `json:"path"`
		State  string `json:"state"`
		Builds int    `json:"builds"`
	} `json:"items"`
	Total   int            `json:"total"`
	States  map[string]int `json:"states"`
	Waiting int            `json:"waiting"`
	Ruled   int            `json:"ruled"`
}

func leadsOf(t *testing.T, r *httpapitest.Reach, who, query string) leadsListed {
	t.Helper()
	var got leadsListed
	httpapitest.Read(t, r, who, "/v1/products/mine/leads"+query, &got)
	return got
}

func TestTheQueueLeavesTheBaselineOutAndCountsIt(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		got := leadsOf(t, r, "internal-reader", "")
		if len(got.Items) != 0 || got.Total != 0 || got.States["baseline"] != 1 {
			t.Fatalf("the queue is %+v; want nothing listed and one baseline lead counted", got)
		}
		searched := leadsOf(t, r, "internal-reader", "?state=baseline")
		if len(searched.Items) != 1 || searched.Items[0].Place != place || searched.Items[0].State != "baseline" ||
			searched.Items[0].Path != "src/a.c" || searched.Items[0].Builds != 1 {
			t.Errorf("the baseline lists %+v; want the seeded lead", searched.Items)
		}
		// Somebody who reads no internal material is told of no lead.
		if got := leadsOf(t, r, "reader", "?state=baseline"); len(got.Items) != 0 || len(got.States) != 0 {
			t.Errorf("a reader of public material is shown %+v", got)
		}
	})
}

func TestALeadPulledInIsInTheQueue(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		at := "/v1/products/mine/leads/" + place + "/escalation"
		// Somebody who reads the lead and does not triage it is answered as
		// closing it as fixed answers them.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodPost, at, `{}`),
			http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/products/mine/leads/nothing-here/escalation", `{}`), http.StatusNotFound)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, at, `{}`); got.Code != http.StatusOK {
			t.Fatalf("pulling the lead in answered %d: %s", got.Code, got.Body)
		}
		got := leadsOf(t, r, "internal-reader", "")
		if len(got.Items) != 1 || got.Items[0].Place != place || got.Items[0].State != "open" {
			t.Fatalf("the queue is %+v; want the lead pulled in", got)
		}
		if got.States["baseline"] != 0 || got.States["open"] != 1 {
			t.Errorf("the lead pulled in is counted %v; want it open", got.States)
		}
		if got := leadState(t, r, place); got != "open" {
			t.Errorf("the lead's evidence says %q; want open", got)
		}
	})
}

func TestALeadUnderAnImportantPathIsInTheQueue(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		const at = "/v1/products/mine/important-paths"
		set := func(body string) {
			t.Helper()
			if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at, body); got.Code != http.StatusNoContent {
				t.Fatalf("marking %s answered %d: %s", body, got.Code, got.Body)
			}
		}
		// A sibling whose name begins the same is not under it.
		set(`{"paths":["sr","src/a"]}`)
		if got := leadsOf(t, r, "internal-reader", ""); len(got.Items) != 0 {
			t.Fatalf("a lead under no important path is in the queue: %+v", got.Items)
		}
		set(`{"paths":["/src/"]}`)
		if got := leadsOf(t, r, "internal-reader", ""); len(got.Items) != 1 || got.Items[0].State != "open" {
			t.Fatalf("a lead under an important path is not in the queue: %+v", got)
		}
		var held struct {
			Paths []string `json:"paths"`
		}
		httpapitest.Read(t, r, "internal-reader", at, &held)
		if len(held.Paths) != 1 || held.Paths[0] != "src" {
			t.Errorf("the product holds %q; want src", held.Paths)
		}
		set(`{"paths":["src/a.c"]}`)
		if got := leadsOf(t, r, "internal-reader", ""); len(got.Items) != 1 {
			t.Errorf("a lead whose own path is important is not in the queue: %+v", got)
		}
		set(`{"paths":[]}`)
		if got := leadsOf(t, r, "internal-reader", ""); len(got.Items) != 0 || got.States["baseline"] != 1 {
			t.Errorf("taking the path off leaves %+v; want the lead back in the baseline", got)
		}
	})
}

func TestAnImportantPathThatSaysNothingIsRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		const at = "/v1/products/mine/important-paths"
		for _, body := range []string{`{"paths":["../etc"]}`, `{"paths":["/"]}`, `{"paths":["src","src/"]}`, `{"paths":["a//b"]}`} {
			httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at, body),
				http.StatusUnprocessableEntity)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "internal-reader", http.MethodPut, at, `{"paths":["src"]}`),
			http.StatusForbidden)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, at, ""), http.StatusForbidden)
	})
}

func TestAClaimWaitingOnASecondPersonTakesItsLeadOutOfTheQueue(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, "/v1/products/mine/leads/"+place+"/escalation", `{}`)
		got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, fmt.Sprintf(leadDecisionAt, place),
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"checked a line above"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("the dismissal answered %d: %s", got.Code, got.Body)
		}
		queue := leadsOf(t, r, "internal-reader", "")
		if len(queue.Items) != 0 || queue.Waiting != 1 || queue.States["open"] != 1 {
			t.Fatalf("the queue is %+v; want the lead left out and counted as waiting", queue)
		}
		if listed := leadsOf(t, r, "internal-reader", "?state=open"); len(listed.Items) != 1 {
			t.Errorf("the open leads are %+v; want the one waiting", listed.Items)
		}
	})
}
