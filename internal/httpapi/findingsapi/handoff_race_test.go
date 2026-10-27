// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// confirmedLead is the seeded lead confirmed, with its occurrence, the
// decision confirming it and the seeded build.
func confirmedLead(t *testing.T, r *httpapitest.Reach) (string, int64, int64) {
	t.Helper()
	occurrence := httpapitest.SeededLead(t, r)
	if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadAt(occurrence)+"/decision",
		`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
		t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
	}
	var decision int64
	if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."decision_id"`).
		Where(`"de"."occurrence_identity" = ?`, occurrence).Limit(1).Scan(t.Context(), &decision); err != nil {
		t.Fatal(err)
	}
	return occurrence, decision, r.TargetOf(t, httpapitest.SeededBuild)
}

// decisionStamp is the stamp a decision holds, zero where it has no row.
func decisionStamp(t *testing.T, r *httpapitest.Reach, decision int64) int {
	t.Helper()
	var stamp int
	if err := r.DB.DB.NewSelect().TableExpr(`"decision_stamp" AS "cs"`).
		ColumnExpr(`COALESCE(MAX("cs"."stamp"), 0)`).Where(`"cs"."decision_id" = ?`, decision).Scan(t.Context(), &stamp); err != nil {
		t.Fatal(err)
	}
	return stamp
}

// handedOff reports whether the lead at an occurrence was handed off.
func handedOff(t *testing.T, r *httpapitest.Reach, occurrence string) bool {
	t.Helper()
	n, err := r.DB.DB.NewSelect().TableExpr(`"lead_handoff" AS "lh"`).
		Where(`"lh"."occurrence_identity" = ?`, occurrence).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// handing is a hand-off of the seeded lead against the seeded build.
func handing(t *testing.T, r *httpapitest.Reach, occurrence string, target int64) analysis.Handing {
	t.Helper()
	located, err := catalog.NewStore(r.DB.DB).Locate(t.Context(), "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	return analysis.Handing{ProductID: located.ProductID, OccurrenceIdentity: occurrence,
		Flaw: finding.Entering{TargetIDs: []int64{target}, Summary: "p leaks"}}
}

// A hand-off changes the stamp of the decision it rests on, as every write
// to the decision does, so the two cannot both commit.
func TestAHandOffRestampsTheDecisionItRestsOn(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, decision, _ := confirmedLead(t, r)
		before := decisionStamp(t, r, decision)
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(occurrence)+"/flaw",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the hand-off answered %d: %s", got.Code, got.Body)
		}
		if got := decisionStamp(t, r, decision); got == before {
			t.Errorf("the confirming decision's stamp is %d after the hand-off; want it changed", got)
		}
	})
}

// A withdrawal of the confirmation landing after a hand-off read it and
// before the hand-off commits leaves no flaw nobody confirmed: the hand-off
// is asked again, finds the lead unconfirmed, and is refused.
func TestAHandOffLosingToAWithdrawalOfItsConfirmationIsRefused(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, decision, target := confirmedLead(t, r)
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "decision", "decision_stamp", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete,
				fmt.Sprintf("/v1/decisions/%d", decision), ""); got.Code != http.StatusNoContent {
				return fmt.Errorf("the withdrawal answered %d: %s", got.Code, got.Body)
			}
			return nil
		})
		subject, err := r.Rights.Resolve(t.Context(), "lead-handler")
		if err != nil {
			t.Fatal(err)
		}
		_, err = analysis.HandOff(t.Context(), hooked, subject, handing(t, r, occurrence, target))
		if rivalErr := rival(); rivalErr != nil {
			t.Fatal(rivalErr)
		}
		if !errors.Is(err, analysis.ErrNotConfirmed) {
			t.Errorf("the hand-off answered %v; want it refused, the confirmation withdrawn", err)
		}
		if handedOff(t, r, occurrence) {
			t.Error("the lead was handed off on a confirmation withdrawn beside it")
		}
	})
}

// A hand-off landing after a withdrawal read that the lead was not handed off
// and before the withdrawal commits leaves the confirmation standing under the
// flaw: the withdrawal is asked again, finds the hand-off, and is refused.
func TestAWithdrawalLosingToAHandOffIsRefused(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, decision, _ := confirmedLead(t, r)
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "lead_handoff", "decision_stamp", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(occurrence)+"/flaw",
				`{"builds":[{"stream":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
				return fmt.Errorf("the hand-off answered %d: %s", got.Code, got.Body)
			}
			return nil
		})
		subject, err := r.Rights.Resolve(t.Context(), "internal-triager")
		if err != nil {
			t.Fatal(err)
		}
		_, err = triage.NewStore(hooked).Withdraw(t.Context(), subject, decision)
		if rivalErr := rival(); rivalErr != nil {
			t.Fatal(rivalErr)
		}
		if !errors.Is(err, triage.ErrLeadHandedOff) {
			t.Errorf("the withdrawal answered %v; want it refused, the lead handed off", err)
		}
		if !handedOff(t, r, occurrence) {
			t.Fatal("the hand-off did not land, so this checks nothing")
		}
		var live int
		if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`COUNT(*)`).
			Where(`"de"."decision_id" = ?`, decision).Where(`"de"."live_key" IS NOT NULL`).
			Scan(t.Context(), &live); err != nil {
			t.Fatal(err)
		}
		if live == 0 {
			t.Error("the confirmation a hand-off rests on was withdrawn beside it")
		}
	})
}

// A move undone after a disclosure read the lead's hand-off and before the
// disclosure writes it leaves the lead internal: the disclosure is asked
// again, finds the lead kept, and leaves it where it is.
func TestAnUndoneMoveLandingWhileADisclosureAppliesKeepsTheLeadInternal(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.HandedOffLead(t, r, true)
		movement := askToDisclose(t, r, flaw)
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "lead_handoff", "lead_handoff", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodDelete, leadAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
				return fmt.Errorf("undoing the move answered %d: %s", got.Code, got.Body)
			}
			return nil
		})
		subject, err := r.Rights.Resolve(t.Context(), "private-dispatcher")
		if err != nil {
			t.Fatal(err)
		}
		_, err = finding.NewStore(hooked).AgreeToMovement(t.Context(), subject, movement)
		if rivalErr := rival(); rivalErr != nil {
			t.Fatal(rivalErr)
		}
		if err != nil {
			t.Fatal(err)
		}
		var held []string
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."visibility"`).
			Where(`"f"."occurrence_identity" = ?`, occurrence).Scan(t.Context(), &held); err != nil {
			t.Fatal(err)
		}
		var decisions []string
		if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."visibility"`).
			Where(`"de"."occurrence_identity" = ?`, occurrence).Scan(t.Context(), &decisions); err != nil {
			t.Fatal(err)
		}
		if len(held) == 0 || len(decisions) == 0 || slices.ContainsFunc(append(held, decisions...), func(v string) bool { return v != "internal" }) {
			t.Errorf("the lead's findings are %v and its decisions %v; want both internal, the lead taken out of the case", held, decisions)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, leadAt(occurrence), ""),
			http.StatusNotFound)
	})
}
