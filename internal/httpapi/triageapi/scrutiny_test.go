// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/triageapi"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// A deferral short enough to stand on nobody's say-so but the proposer's,
// which is the exception the rule carries and the pattern this report exists
// to make visible across a program.
//
// Counted from today. A deferral returns on a date still to come, so a fixed
// one is refused from the day it arrives — and the refusal is a test failing
// for the calendar rather than for the behavior it names. A week is short
// against the threshold that asks for a second person, which is thirty days.
func shortDeferral() string {
	returns := time.Now().UTC().AddDate(0, 0, 7).Format(time.DateOnly)
	return `{"outcome":"deferred","deferred_until":"` + returns + `",` +
		`"reasoning":"Not this sprint; the release is next week."}`
}

func scrutiny(t *testing.T, r *httpapitest.Reach, who, query string) struct {
	Alone  []triageapi.UnagreedBody       `json:"alone"`
	Bulk   []triageapi.BulkApprovalBody   `json:"bulk"`
	Pairs  []triageapi.PairingBody        `json:"pairs"`
	Lapsed []triageapi.LapsedApprovalBody `json:"lapsed"`
	Grew   []triageapi.GrownBody          `json:"grew"`
	Agreed int                            `json:"agreed"`
} {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/approvals/scrutiny"+query, "")
	if got.Code != http.StatusOK {
		t.Fatalf("%s asking how approvals are going answered %d: %s",
			who, got.Code, got.Body.String())
	}
	var out struct {
		Alone  []triageapi.UnagreedBody       `json:"alone"`
		Bulk   []triageapi.BulkApprovalBody   `json:"bulk"`
		Pairs  []triageapi.PairingBody        `json:"pairs"`
		Lapsed []triageapi.LapsedApprovalBody `json:"lapsed"`
		Grew   []triageapi.GrownBody          `json:"grew"`
		Agreed int                            `json:"agreed"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
		t.Fatalf("it is not JSON: %v (%s)", err, got.Body.String())
	}
	return out
}

func TestRiskStandingOnOnePersonIsReportedWithWhatItClaimed(t *testing.T) {
	// The whole point of the report. The control cannot be bypassed — the
	// proposer may never approve their own decision — so what is worth reporting
	// is where the rule did not apply. A short deferral is deliberately exempt
	// and is ordinary triage one at a time; it is the pattern across a program
	// that nothing else shows.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)

		if before := scrutiny(t, r, "private-triage", ""); len(before.Alone) != 0 {
			t.Fatalf("something stands alone before anything was decided: %+v", before.Alone)
		}

		r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", shortDeferral())

		after := scrutiny(t, r, "private-triage", "")
		if len(after.Alone) != 1 {
			t.Fatalf("%d kinds stand alone, want the deferral: %+v", len(after.Alone), after.Alone)
		}
		if after.Alone[0].Outcome != "deferred" {
			t.Errorf("what stands alone is %q, want the deferral", after.Alone[0].Outcome)
		}
		if after.Alone[0].Decisions != 1 || after.Alone[0].Rows < 1 {
			t.Errorf("it stands alone as %d decisions over %d rows",
				after.Alone[0].Decisions, after.Alone[0].Rows)
		}
	})
}

func TestWhatTwoPeopleAgreedToIsNotReportedAsStandingAlone(t *testing.T) {
	// The other direction, which is what stops the report being a list of
	// everything. A dismissal needs a second person, gets one, and so has
	// nothing to answer for.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)

		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decision), `{"batch":"tuesday"}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		out := scrutiny(t, r, "private-triage", "")
		for _, row := range out.Alone {
			if row.Outcome == "not-applicable" {
				t.Errorf("a dismissal two people agreed to is reported as standing alone: %+v", row)
			}
		}

		// And it is reported as what it is: an agreement between two named
		// people, given as one act.
		if len(out.Pairs) != 1 {
			t.Fatalf("%d pairs agreed, want the one: %+v", len(out.Pairs), out.Pairs)
		}
		if out.Pairs[0].Proposer != "triager" || out.Pairs[0].Approver != "reviewer" {
			t.Errorf("the pair reads %q and %q", out.Pairs[0].Proposer, out.Pairs[0].Approver)
		}
		if out.Pairs[0].Share != 100 {
			t.Errorf("the only pair holds %d%% of what was agreed", out.Pairs[0].Share)
		}
		if len(out.Bulk) != 1 || out.Bulk[0].Batch != "tuesday" {
			t.Errorf("the batch it was agreed under is not reported: %+v", out.Bulk)
		}
		if out.Bulk[0].ApprovedBy != "reviewer" {
			t.Errorf("the batch names %q as the approver", out.Bulk[0].ApprovedBy)
		}
	})
}

func TestScrutinyRefusesAProductTheAskerMayNotRead(t *testing.T) {
	// Resolved against what the caller may see, and refused the same way a
	// name nobody ever declared is. Answering "no approvals there" for a real
	// product and 404 for an invented one would turn this into a way to ask
	// which products a deployment has, one guess at a time.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", shortDeferral())

		real := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/approvals/scrutiny?product=theirs", "")
		invented := httpapitest.AsPerson(t, r, "private-triage", http.MethodGet,
			"/v1/approvals/scrutiny?product=no-such-product", "")
		if real.Code != http.StatusNotFound {
			t.Errorf("a product they may not read answered %d, want 404: %s",
				real.Code, real.Body.String())
		}
		if invented.Code != real.Code {
			t.Errorf("a real product answers %d and an invented one %d, which tells "+
				"somebody which names exist", real.Code, invented.Code)
		}
	})
}

func TestADecisionCoveringMoreThanWasAgreedToIsReported(t *testing.T) {
	// A decision reaches by matching, so a build appearing afterwards is covered
	// with nobody acting and nobody having agreed to the larger number. What
	// somebody consented to is recorded at the moment of consent precisely
	// because it cannot be recovered later; this is the section that reads the
	// two against each other.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		decision, ids := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		r.Agreed(t, decision)

		// Nothing has appeared since, so nothing covers more than was agreed.
		if out := scrutiny(t, r, "private-triage", ""); len(out.Grew) != 0 {
			t.Fatalf("something already covers more than it was agreed to cover: %+v", out.Grew)
		}

		// The reach the approver actually agreed to, made smaller than what the
		// decision reaches. A second build would do this the way a deployment
		// does, and what is being pinned is the comparison rather than the
		// route by which the two came apart.
		if _, err := r.DB.DB.NewUpdate().
			Table("decision_approval").
			Set(`"covered" = ?`, len(ids)-1).
			Where(`"decision_id" = ?`, decision).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		out := scrutiny(t, r, "private-triage", "")
		if len(out.Grew) != 1 {
			t.Fatalf("%d decisions cover more than was agreed to, want the one: %+v",
				len(out.Grew), out.Grew)
		}
		grown := out.Grew[0]
		if grown.DecisionID != decision {
			t.Errorf("it names decision %d, want %d", grown.DecisionID, decision)
		}
		if grown.Covered != len(ids)-1 || grown.CoversNow != len(ids) {
			t.Errorf("it reads %d agreed against %d now, want %d against %d",
				grown.Covered, grown.CoversNow, len(ids)-1, len(ids))
		}
		if grown.ApprovedBy != "reviewer" {
			t.Errorf("it names %q as the approver", grown.ApprovedBy)
		}
	})
}

func TestAnAdministratorWhoCouldNotApproveNowIsListed(t *testing.T) {
	// An administrator holds no role ungranted, so one whose right to approve
	// was withdrawn could not agree today and is listed like anybody else.
	// Named in configuration is administration too.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		r.Agreed(t, decision)
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/reviewer/roles/mine/approver", ""); got.Code >= 300 {
			t.Fatalf("withdrawing the right answered %d: %s", got.Code, got.Body.String())
		}
		lapsedBy := func() []string {
			t.Helper()
			var who []string
			for _, row := range scrutiny(t, r, "private-triage", "").Lapsed {
				who = append(who, row.ApprovedBy)
			}
			return who
		}
		if who := lapsedBy(); len(who) != 1 || who[0] != "reviewer" {
			t.Fatalf("with the right withdrawn, the lapsed approvals are by %v", who)
		}

		if _, err := r.Rights.NameBootstrapAdmins(t.Context(), []string{"reviewer"}); err != nil {
			t.Fatal(err)
		}
		if who := lapsedBy(); len(who) != 1 || who[0] != "reviewer" {
			t.Errorf("an administrator who could not approve now is left off the list: %v", who)
		}
	})
}

func TestATriagerWhoMayStillApproveIsNotListed(t *testing.T) {
	// A triager agrees to somebody else's decision without the approver
	// capability, and still holding triage there could agree today.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		r.AgreedBy(t, "assigner", decision)
		for _, row := range scrutiny(t, r, "private-triage", "").Lapsed {
			if row.DecisionID == decision {
				t.Errorf("an approval by a triager who still triages there is listed as lost: %+v", row)
			}
		}
	})
}

func TestAnAgreementLostOnOneRowCountsEveryRowItCovers(t *testing.T) {
	// The right is asked of each row at its own visibility, and the
	// decision is listed with every row the agreement covers: the reach of
	// the agreement is what an auditor weighs.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		decision, ids := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		r.Agreed(t, decision)
		var row triage.DecisionOccurrence
		if err := r.DB.DB.NewSelect().Model(&row).Where(`"de"."id" = ?`, ids[0]).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if row.Visibility != access.Public {
			t.Fatalf("the decision is %s; this needs a disclosed one beside an undisclosed row", row.Visibility)
		}
		// An undisclosed row of the same decision, which the approver, who
		// reads disclosed work alone, could not agree to now.
		hidden := row
		hidden.ID, hidden.LiveKey, hidden.OccurrenceIdentity, hidden.Visibility = 0, nil, "elsewhere", access.Private
		if _, err := r.DB.DB.NewInsert().Model(&hidden).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		var listed []triageapi.LapsedApprovalBody
		for _, one := range scrutiny(t, r, "private-triage", "").Lapsed {
			if one.DecisionID == decision {
				listed = append(listed, one)
			}
		}
		if len(listed) != 1 || listed[0].Rows != len(ids)+1 {
			t.Errorf("the agreement is listed as %+v; want it once, covering %d rows", listed, len(ids)+1)
		}
	})
}

// A pair's share is of everything agreed, not of the pairs listed.
//
// The list is cut at the limit, and a share taken of the pairs left standing
// reports one pair of two as holding everything, which is the concentration
// the report exists to find, and it is not there.
func TestAPairsShareIsOfEverythingAgreed(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		for _, each := range []struct{ who, issue string }{
			{"triager", "CVE-2026-9999"}, {"private-triage", "CVE-2026-1000"},
		} {
			decision, _ := r.Claimed(t, each.who, each.issue, "linux-image", httpapitest.Dismissal)
			r.Agreed(t, decision)
		}

		out := scrutiny(t, r, "private-triage", "?limit=1")
		if len(out.Pairs) != 1 {
			t.Fatalf("%d pairs listed under a limit of one", len(out.Pairs))
		}
		if out.Agreed != 2 {
			t.Errorf("agreed is %d, want both pairs' rows", out.Agreed)
		}
		if out.Pairs[0].Share != 50 {
			t.Errorf("one pair of two equal ones holds %d%% of what was agreed", out.Pairs[0].Share)
		}
	})
}

func TestAConfirmedCodeFindingIsNoExceptionToTheSecondPersonRule(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decideCodeFinding(t, r, occurrence, `{"outcome":"confirmed","reasoning":"the free runs on the error path"}`)
		if got := scrutiny(t, r, "security-testing-reviewer", ""); len(got.Alone) != 0 {
			t.Errorf("a confirmed code finding is reported as standing alone: %+v", got.Alone)
		}
	})
}

func TestACodeFindingDismissalStandingAloneIsReportedInAPublishedOutcome(t *testing.T) {
	// A code finding's dismissal hides risk as a vulnerability's does, so it
	// is what the report exists to surface when nobody else stands behind it,
	// and it is reported in a word the published vocabulary holds.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		decided := decideCodeFinding(t, r, occurrence,
			`{"outcome":"dismissed","reason":"used_in_tests","reasoning":"only the test harness calls it"}`)
		if got := httpapitest.AsPerson(t, r, "security-testing-reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decided.DecisionID), `{}`); got.Code != http.StatusOK {
			t.Fatalf("the approval answered %d: %s", got.Code, got.Body)
		}
		// The one agreement standing is its proposer's own, which nothing
		// here records and an imported record can hold.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"decision_approval"`).
			Set(`"approved_by" = (SELECT "de"."proposed_by" FROM "decision_occurrence" AS "de"`+
				` WHERE "de"."decision_id" = ? LIMIT 1)`, decided.DecisionID).
			Where(`"decision_id" = ?`, decided.DecisionID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		out := scrutiny(t, r, "security-testing-reviewer", "")
		var dismissed *triageapi.UnagreedBody
		for i := range out.Alone {
			if out.Alone[i].Outcome == "dismissed" {
				dismissed = &out.Alone[i]
			}
		}
		if dismissed == nil {
			t.Fatalf("what stands alone is %+v; want the code finding's dismissal", out.Alone)
		}
		if !slices.Contains(triage.OutcomesThatHideRisk(), triage.Outcome(dismissed.Outcome)) {
			t.Errorf("the report says %q, which the published outcomes that hide risk %v do not hold",
				dismissed.Outcome, triage.OutcomesThatHideRisk())
		}
	})
}
