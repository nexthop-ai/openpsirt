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
			leadsAtMaster+overflow+"/fixed", `{"because":"the bounds check landed"}`))
		refusedAsEnded(t, "pulling a lead in", httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost,
			"/v1/products/mine/leads/"+overflow+"/escalation", `{}`))
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
		endMaster(t, r)

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
		var leak finding.Finding
		if err := r.DB.DB.NewSelect().Model(&leak).Where(`"f"."place_identity" = ?`, place).
			Where(`"f"."closed_at" IS NULL`).Limit(1).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		leak.ID, leak.TargetID = 0, other
		if _, err := r.DB.DB.NewInsert().Model(&leak).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		endMaster(t, r)

		decideLead(t, r, place, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		var decided int
		if err := r.DB.DB.NewSelect().Table("decision").ColumnExpr("COUNT(*)").
			Where(`"place_identity" = ?`, kin[0]).Scan(ctx, &decided); err != nil {
			t.Fatal(err)
		}
		if decided != 0 {
			t.Errorf("a judgment was recorded %d times at kin seen only past its end of life", decided)
		}
	})
}
