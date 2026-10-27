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

// confirmedCodeFinding is the seeded code finding confirmed, with its occurrence, the
// decision confirming it and the seeded build.
func confirmedCodeFinding(t *testing.T, r *httpapitest.Reach) (string, int64, int64) {
	t.Helper()
	occurrence := httpapitest.SeededCodeFinding(t, r)
	if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFindingAt(occurrence)+"/decision",
		`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
		t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
	}
	var decision int64
	if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."decision_id"`).
		Where(`"de"."occurrence_identity" = ?`, occurrence).Limit(1).Scan(t.Context(), &decision); err != nil {
		t.Fatal(err)
	}
	return occurrence, decision, r.BuildOf(t, httpapitest.SeededBuild)
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

// recordedAsFlaw reports whether the code finding at an occurrence was recorded as a flaw.
func recordedAsFlaw(t *testing.T, r *httpapitest.Reach, occurrence string) bool {
	t.Helper()
	n, err := r.DB.DB.NewSelect().TableExpr(`"code_finding_flaw" AS "lh"`).
		Where(`"lh"."occurrence_identity" = ?`, occurrence).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// handing is a flaw record of the seeded code finding against the seeded build.
func handing(t *testing.T, r *httpapitest.Reach, occurrence string, build int64) analysis.Recording {
	t.Helper()
	located, err := catalog.NewStore(r.DB.DB).Locate(t.Context(), "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	return analysis.Recording{ProductID: located.ProductID, OccurrenceIdentity: occurrence,
		Flaw: finding.Entering{BuildIDs: []int64{build}, Summary: "p leaks"}}
}

// A flaw record changes the stamp of the decision it rests on, as every write
// to the decision does, so the two cannot both commit.
func TestARecordAsFlawRestampsTheDecisionItRestsOn(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, decision, _ := confirmedCodeFinding(t, r)
		before := decisionStamp(t, r, decision)
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrence)+"/flaw",
			`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
			t.Fatalf("the flaw record answered %d: %s", got.Code, got.Body)
		}
		if got := decisionStamp(t, r, decision); got == before {
			t.Errorf("the confirming decision's stamp is %d after the flaw record; want it changed", got)
		}
	})
}

// A withdrawal of the confirmation landing after a flaw record read it and
// before the flaw record commits leaves no flaw nobody confirmed: the flaw record
// is asked again, finds the code finding unconfirmed, and is refused.
func TestARecordAsFlawLosingToAWithdrawalOfItsConfirmationIsRefused(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, decision, build := confirmedCodeFinding(t, r)
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "decision", "decision_stamp", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodDelete,
				fmt.Sprintf("/v1/decisions/%d", decision), ""); got.Code != http.StatusNoContent {
				return fmt.Errorf("the withdrawal answered %d: %s", got.Code, got.Body)
			}
			return nil
		})
		subject, err := r.Rights.Resolve(t.Context(), "code-finding-handler")
		if err != nil {
			t.Fatal(err)
		}
		_, err = analysis.RecordAsFlaw(t.Context(), hooked, subject, handing(t, r, occurrence, build))
		if rivalErr := rival(); rivalErr != nil {
			t.Fatal(rivalErr)
		}
		if !errors.Is(err, analysis.ErrNotConfirmed) {
			t.Errorf("the flaw record answered %v; want it refused, the confirmation withdrawn", err)
		}
		if recordedAsFlaw(t, r, occurrence) {
			t.Error("the code finding was recorded as a flaw on a confirmation withdrawn beside it")
		}
	})
}

// A flaw record landing after a withdrawal read that the code finding was not recorded as a flaw
// and before the withdrawal commits leaves the confirmation standing under the
// flaw: the withdrawal is asked again, finds the flaw record, and is refused.
func TestAWithdrawalLosingToARecordAsFlawIsRefused(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, decision, _ := confirmedCodeFinding(t, r)
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "code_finding_flaw", "decision_stamp", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrence)+"/flaw",
				`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],"summary":"p leaks"}`); got.Code != http.StatusCreated {
				return fmt.Errorf("the flaw record answered %d: %s", got.Code, got.Body)
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
		if !errors.Is(err, triage.ErrCodeFindingRecordedAsFlaw) {
			t.Errorf("the withdrawal answered %v; want it refused, the code finding recorded as a flaw", err)
		}
		if !recordedAsFlaw(t, r, occurrence) {
			t.Fatal("the flaw record did not land, so this checks nothing")
		}
		var live int
		if err := r.DB.DB.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`COUNT(*)`).
			Where(`"de"."decision_id" = ?`, decision).Where(`"de"."live_key" IS NOT NULL`).
			Scan(t.Context(), &live); err != nil {
			t.Fatal(err)
		}
		if live == 0 {
			t.Error("the confirmation a flaw record rests on was withdrawn beside it")
		}
	})
}

// A removal from disclosure after a disclosure read the code finding's flaw record and before the
// disclosure writes it leaves the code finding internal: the disclosure is asked
// again, finds the code finding internal only, and leaves it internal.
func TestARemovalFromDisclosureLandingWhileADisclosureAppliesKeepsTheCodeFindingInternal(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, true)
		movement := askToDisclose(t, r, flaw)
		hooked, rival := dbtest.RivalAfterRead(t, r.DB, "code_finding_flaw", "code_finding_flaw", 3*time.Second, func() error {
			if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodDelete, codeFindingAt(occurrence)+"/flaw/disclosure", ""); got.Code != http.StatusNoContent {
				return fmt.Errorf("taking it out of disclosure answered %d: %s", got.Code, got.Body)
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
			t.Errorf("the code finding's findings are %v and its decisions %v; want both internal, the code finding taken out of disclosure", held, decisions)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet, codeFindingAt(occurrence), ""),
			http.StatusNotFound)
	})
}
