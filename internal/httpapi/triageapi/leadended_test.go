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

const leadsAtMaster = "/v1/products/mine/streams/master/variants/broadcom/leads/"

// endMaster puts the seeded release past its end of life.
func endMaster(t *testing.T, r *httpapitest.Reach) {
	t.Helper()
	ended := time.Now().UTC().Add(-48 * time.Hour).Truncate(24 * time.Hour)
	if _, err := r.DB.DB.NewUpdate().TableExpr(`"stream"`).Set(`"eol_on" = ?`, ended).
		Where(`"name" = ?`, "master").Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// alsoOnV1 opens the lead at a place on a release v1, still in support, as
// well as on the seeded one.
func alsoOnV1(t *testing.T, r *httpapitest.Reach, place string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	mine, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.DeclareStream(ctx, mine.ID, "v1", catalog.Branch, nil); err != nil {
		t.Fatal(err)
	}
	other := r.TargetOf(t, httpapitest.Build{Product: "mine", Stream: "v1", Variant: "broadcom"})
	var lead finding.Finding
	if err := r.DB.DB.NewSelect().Model(&lead).Where(`"f"."place_identity" = ?`, place).
		Where(`"f"."closed_at" IS NULL`).Limit(1).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	lead.ID, lead.TargetID = 0, other
	if _, err := r.DB.DB.NewInsert().Model(&lead).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// decisionsAt is how many decisions were ever recorded at a place.
func decisionsAt(t *testing.T, r *httpapitest.Reach, place string) int {
	t.Helper()
	var n int
	if err := r.DB.DB.NewSelect().Table("decision").ColumnExpr("COUNT(*)").
		Where(`"place_identity" = ?`, place).Scan(t.Context(), &n); err != nil {
		t.Fatal(err)
	}
	return n
}

// refusedAsEnded fails unless a request was refused because its lead is past
// its end of life.
func refusedAsEnded(t *testing.T, what string, got *httptest.ResponseRecorder) {
	t.Helper()
	if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "end of life") {
		t.Errorf("%s past its end of life answered %d: %s; want 409 for the end of life", what, got.Code, got.Body)
	}
}

func TestALeadPastItsEndOfLifeRefusesEveryChangeButAnAgreementAndAMove(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		kept, _ := httpapitest.HandedOffLead(t, r, false)
		overflowsIn(t, r, "src/c.c", "416", "787", 3)
		var overflow string
		for _, item := range leadsOf(t, r, "internal-reader", "?state=open").Items {
			if item.Place != kept {
				overflow = item.Place
			}
		}
		if overflow == "" {
			t.Fatal("the overflow in src/c.c did not open a lead")
		}
		waiting := decideLead(t, r, overflow,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked by the caller"}`)
		// Not reproduced, so a fixed closure is refused for nothing but the
		// end of life.
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.OtherToolRun("cppcheck", "overflow", "787", "src/c.c"))
		endMaster(t, r)

		refusedAsEnded(t, "a fixed closure", httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			leadsAtMaster+overflow+"/fixed",
			httpapitest.FixedBody(t, r, leadsAtMaster+overflow, "the bounds check landed")))
		refusedAsEnded(t, "a hand-off", httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost,
			leadsAtMaster+overflow+"/hand-off",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"n overflows","move":false}`))

		if got := httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", waiting.ClaimID), `{}`); got.Code != http.StatusOK {
			t.Errorf("agreeing to a claim standing at a lead past its end of life answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPut, leadsAtMaster+kept+"/move", ""); got.Code != http.StatusNoContent {
			t.Errorf("moving a handed-off lead past its end of life answered %d: %s", got.Code, got.Body)
		}
	})
}

func TestALapsedClaimAtALeadPastItsEndOfLifeIsNotReaffirmed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := httpapitest.SeededLead(t, r)
		decided := decideLead(t, r, place,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"freed by the caller"}`)
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", decided.ClaimID), `{}`)
		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.LeadRunAt(12))
		// Two lines down pairs it on its nearest line, which lapses it.
		httpapitest.ApplyRun(t, r, time.Now().UTC(), httpapitest.LeadRunAt(14))
		if got := leadState(t, r, place); got == "dismissed" {
			t.Fatal("a dismissal paired only on its nearest line did not lapse")
		}
		if listed := toReaffirm(t, r, "internal-triager"); len(listed) != 1 {
			t.Fatalf("%d claims are listed to re-affirm before the end of life; want the one lapsed, "+
				"so this checks nothing", len(listed))
		}
		endMaster(t, r)

		if listed := toReaffirm(t, r, "internal-triager"); len(listed) != 0 {
			t.Errorf("a claim at a lead past its end of life alone is listed to re-affirm: %+v", listed)
		}
		var page struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "internal-triager", "/v1/to-reaffirm", &page)
		if page.Total != 0 {
			t.Errorf("the claims to re-affirm total %d; want none", page.Total)
		}
		var claim struct {
			Reaffirmable bool `json:"reaffirmable"`
		}
		httpapitest.Read(t, r, "internal-triager", fmt.Sprintf("/v1/claims/%d", decided.ClaimID), &claim)
		if claim.Reaffirmable {
			t.Error("a claim at a lead past its end of life alone reads as re-affirmable")
		}
		refusedAsEnded(t, "re-affirming a claim", httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", decided.ClaimID),
			`{"reasoning":"still freed by the caller after the move"}`))
		refusedAsEnded(t, "re-affirming claims together", httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/reaffirmations",
			fmt.Sprintf(`{"claims":[%d],"reasoning":"still freed by the caller after the move"}`, decided.ClaimID)))
		if got := leadState(t, r, place); got == "dismissed" {
			t.Errorf("a lead past its end of life is %q after the refusals; want it as it stood", got)
		}
	})
}

func TestAJudgmentAboutALeadStillInSupportReachesNoKinPastItsEndOfLife(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, kin := besideTheLeak(t, r, 4)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4", kin)
		}
		// The leak is also seen on a release still in support, and its kin
		// only on the seeded one.
		alsoOnV1(t, r, place)
		endMaster(t, r)

		decideLead(t, r, place, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if decided := decisionsAt(t, r, kin[0]); decided != 0 {
			t.Errorf("a judgment was recorded %d times at kin seen only past its end of life", decided)
		}
	})
}

func TestAReaffirmationRemakesAClaimOnlyAtLeadsStillInSupport(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, kin := besideTheLeak(t, r, 4)
		if len(kin) != 1 {
			t.Fatalf("the leak's kin are %v; want the overflow on line 4", kin)
		}
		decided := decideLead(t, r, place,
			`{"outcome":"dismissed","reason":"false_positive","reasoning":"the length is checked by the caller"}`)
		httpapitest.AsPerson(t, r, "internal-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", decided.ClaimID), `{}`)
		if got := decisionsAt(t, r, kin[0]); got != 1 {
			t.Fatalf("the claim reached its kin %d times; want once, so this checks nothing", got)
		}
		lapsed := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"decision"`).
			Set(`"state" = ?`, triage.LapsedState).Set(`"live_key" = ?`, nil).Set(`"ended_at" = ?`, lapsed).
			Where(`"claim_id" = ?`, decided.ClaimID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		// The leak is also on a release still in support, and its kin only on
		// the one past its end of life.
		alsoOnV1(t, r, place)
		endMaster(t, r)

		listed := toReaffirm(t, r, "internal-triager")
		if len(listed) != 1 || listed[0].Claim.ID != decided.ClaimID || listed[0].Places != 1 {
			t.Fatalf("listed to re-affirm: %+v; want claim %d at its one place still in support",
				listed, decided.ClaimID)
		}
		// Every claim listed, as selecting all of them sends it.
		claims := make([]string, 0, len(listed))
		for _, item := range listed {
			claims = append(claims, fmt.Sprint(item.Claim.ID))
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, "/v1/reaffirmations",
			fmt.Sprintf(`{"claims":[%s],"reasoning":"still checked by the caller"}`, strings.Join(claims, ","))); got.Code != http.StatusCreated {
			t.Fatalf("re-affirming every claim listed answered %d: %s", got.Code, got.Body)
		}
		if got := decisionsAt(t, r, place); got != 2 {
			t.Errorf("the lead still in support holds %d decisions; want the lapsed one and its re-making", got)
		}
		if got := decisionsAt(t, r, kin[0]); got != 1 {
			t.Errorf("the kin past its end of life holds %d decisions; want the lapsed one alone", got)
		}
	})
}
