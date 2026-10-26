// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// confirmedLead is the seeded lead confirmed, with its place, the claim
// confirming it and the seeded build.
func confirmedLead(t *testing.T, r *httpapitest.Reach) (string, int64, int64) {
	t.Helper()
	place := httpapitest.SeededLead(t, r)
	if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadAt(place)+"/decision",
		`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
		t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
	}
	var claim int64
	if err := r.DB.DB.NewSelect().TableExpr(`"decision" AS "de"`).ColumnExpr(`"de"."claim_id"`).
		Where(`"de"."place_identity" = ?`, place).Limit(1).Scan(t.Context(), &claim); err != nil {
		t.Fatal(err)
	}
	return place, claim, r.TargetOf(t, httpapitest.SeededBuild)
}

// claimStamp is the stamp a claim holds, zero where it has no row.
func claimStamp(t *testing.T, r *httpapitest.Reach, claim int64) int {
	t.Helper()
	var stamp int
	if err := r.DB.DB.NewSelect().TableExpr(`"claim_stamp" AS "cs"`).
		ColumnExpr(`COALESCE(MAX("cs"."stamp"), 0)`).Where(`"cs"."claim_id" = ?`, claim).Scan(t.Context(), &stamp); err != nil {
		t.Fatal(err)
	}
	return stamp
}

// handedOff reports whether the lead at a place was handed off.
func handedOff(t *testing.T, r *httpapitest.Reach, place string) bool {
	t.Helper()
	n, err := r.DB.DB.NewSelect().TableExpr(`"lead_handoff" AS "lh"`).
		Where(`"lh"."place_identity" = ?`, place).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// handing is a hand-off of the seeded lead against the seeded build.
func handing(t *testing.T, r *httpapitest.Reach, place string, target int64) analysis.Handing {
	t.Helper()
	located, err := catalog.NewStore(r.DB.DB).Locate(t.Context(), "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	return analysis.Handing{ProductID: located.ProductID, PlaceIdentity: place,
		Flaw: finding.Entering{TargetIDs: []int64{target}, Summary: "p leaks"}}
}

// A hand-off changes the stamp of the claim it rests on, as every write to
// the claim does, so the two cannot both commit.
func TestAHandOffRestampsTheClaimItRestsOn(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, claim, _ := confirmedLead(t, r)
		before := claimStamp(t, r, claim)
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(place)+"/hand-off",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the hand-off answered %d: %s", got.Code, got.Body)
		}
		if got := claimStamp(t, r, claim); got == before {
			t.Errorf("the confirming claim's stamp is %d after the hand-off; want it changed", got)
		}
	})
}

// A withdrawal of the confirmation landing after a hand-off read it and
// before the hand-off commits leaves no flaw nobody confirmed: the hand-off
// is asked again, finds the lead unconfirmed, and is refused.
func TestAHandOffLosingToAWithdrawalOfItsConfirmationIsRefused(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, claim, target := confirmedLead(t, r)
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "claim", "claim_stamp", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete,
				fmt.Sprintf("/v1/claims/%d", claim), ""); got.Code != http.StatusNoContent {
				return fmt.Errorf("the withdrawal answered %d: %s", got.Code, got.Body)
			}
			return nil
		})
		subject, err := r.Rights.Resolve(t.Context(), "lead-handler")
		if err != nil {
			t.Fatal(err)
		}
		_, err = analysis.HandOff(t.Context(), hooked, subject, handing(t, r, place, target))
		if rivalErr := rival(); rivalErr != nil {
			t.Fatal(rivalErr)
		}
		if !errors.Is(err, analysis.ErrNotConfirmed) {
			t.Errorf("the hand-off answered %v; want it refused, the confirmation withdrawn", err)
		}
		if handedOff(t, r, place) {
			t.Error("the lead was handed off on a confirmation withdrawn beside it")
		}
	})
}

// A hand-off landing after a withdrawal read that the lead was not handed off
// and before the withdrawal commits leaves the confirmation standing under the
// flaw: the withdrawal is asked again, finds the hand-off, and is refused.
func TestAWithdrawalLosingToAHandOffIsRefused(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place, claim, _ := confirmedLead(t, r)
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "lead_handoff", "claim_stamp", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(place)+"/hand-off",
				`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
				return fmt.Errorf("the hand-off answered %d: %s", got.Code, got.Body)
			}
			return nil
		})
		subject, err := r.Rights.Resolve(t.Context(), "internal-triager")
		if err != nil {
			t.Fatal(err)
		}
		err = triage.NewStore(hooked).Withdraw(t.Context(), subject, claim)
		if rivalErr := rival(); rivalErr != nil {
			t.Fatal(rivalErr)
		}
		if !errors.Is(err, triage.ErrLeadHandedOff) {
			t.Errorf("the withdrawal answered %v; want it refused, the lead handed off", err)
		}
		if !handedOff(t, r, place) {
			t.Fatal("the hand-off did not land, so this checks nothing")
		}
		var live int
		if err := r.DB.DB.NewSelect().TableExpr(`"decision" AS "de"`).ColumnExpr(`COUNT(*)`).
			Where(`"de"."claim_id" = ?`, claim).Where(`"de"."live_key" IS NOT NULL`).
			Scan(t.Context(), &live); err != nil {
			t.Fatal(err)
		}
		if live == 0 {
			t.Error("the confirmation a hand-off rests on was withdrawn beside it")
		}
	})
}
