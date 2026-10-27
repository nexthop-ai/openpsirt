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

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// reaffirmedMany is the answer to one act over many decisions.
type reaffirmedMany struct {
	Decisions []struct {
		PreviousDecisionID  int64   `json:"previous_decision_id"`
		DecisionID          int64   `json:"decision_id"`
		DecisionOccurrences []int64 `json:"decision_occurrences"`
		Waiting             bool    `json:"waiting"`
	} `json:"decisions"`
}

func reaffirmingMany(t *testing.T, r *httpapitest.Reach, who string, decisions ...int64) (int, string, reaffirmedMany) {
	t.Helper()
	named := make([]string, 0, len(decisions))
	for _, id := range decisions {
		named = append(named, fmt.Sprint(id))
	}
	got := httpapitest.AsPerson(t, r, who, http.MethodPost, "/v1/reaffirmations",
		`{"reasoning":"Checked the changelog; none of these subsystems moved.",`+
			`"decisions":[`+strings.Join(named, ",")+`]}`)
	var out reaffirmedMany
	if got.Code == http.StatusCreated {
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return got.Code, got.Body.String(), out
}

// toReaffirm reads the list of lapsed decisions a person has to re-affirm.
func toReaffirm(t *testing.T, r *httpapitest.Reach, who string) (items []struct {
	Decision struct {
		ID int64 `json:"id"`
	} `json:"decision"`
	CodeMoved   bool   `json:"code_moved"`
	RatedWorse  bool   `json:"rated_worse"`
	Was         string `json:"was"`
	Now         string `json:"now"`
	Occurrences int    `json:"occurrences"`
}) {
	t.Helper()
	var page struct {
		Items []struct {
			Decision struct {
				ID int64 `json:"id"`
			} `json:"decision"`
			CodeMoved   bool   `json:"code_moved"`
			RatedWorse  bool   `json:"rated_worse"`
			Was         string `json:"was"`
			Now         string `json:"now"`
			Occurrences int    `json:"occurrences"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, who, "/v1/to-reaffirm", &page)
	return page.Items
}

func TestOneActReAffirmsSeveralLapsedDecisions(t *testing.T) {
	// A version bump on a large component lapses many decisions at once, and each
	// is a separate decision with its own outcome and justification. One act
	// re-makes all of them under one reason, each keeping what it said.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		absent := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		unreachable := r.AgreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		r.CurlMovedTo(t, "8.6.0")

		code, body, out := reaffirmingMany(t, r, "triager", absent, unreachable)
		if code != http.StatusCreated {
			t.Fatalf("re-affirming the selection answered %d: %s", code, body)
		}
		if len(out.Decisions) != 2 {
			t.Fatalf("the act re-made %d decisions, want the two behind the selection: %s",
				len(out.Decisions), body)
		}
		for _, one := range out.Decisions {
			if one.PreviousDecisionID != absent && one.PreviousDecisionID != unreachable {
				t.Errorf("the act re-made decision %d, which nothing selected covers",
					one.PreviousDecisionID)
			}
			if len(one.DecisionOccurrences) != 2 {
				t.Errorf("decision %d was re-made at %d occurrences, want both of the fold",
					one.PreviousDecisionID, len(one.DecisionOccurrences))
			}
			if one.Waiting {
				t.Errorf("decision %d waits for a second person with nothing changed",
					one.PreviousDecisionID)
			}
			// Each keeps its own justification: the reason is shared and the
			// argument is not.
			var was, now string
			if err := r.DB.DB.NewSelect().Table("decision").Column("justification").
				Where(`"id" = ?`, one.PreviousDecisionID).Scan(t.Context(), &was); err != nil {
				t.Fatal(err)
			}
			if err := r.DB.DB.NewSelect().Table("decision").Column("justification").
				Where(`"id" = ?`, one.DecisionID).Scan(t.Context(), &now); err != nil {
				t.Fatal(err)
			}
			if now != was {
				t.Errorf("decision %d was re-made as %q, want its own %q",
					one.PreviousDecisionID, now, was)
			}
		}
	})
}

func TestASeverityRiseSendsBackOnlyTheDecisionItBearsOn(t *testing.T) {
	// Each decision carries its own earlier agreement, so one that needs a second
	// look says nothing about the others. A rise bears on a decision that nothing
	// an attacker controls reaches the code, and not on one that the code is
	// absent.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		absent := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		unreachable := r.AgreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		for _, issue := range []string{"CVE-2026-CURL1", "CVE-2026-CURL2"} {
			if _, err := r.DB.DB.NewUpdate().Table("vulnerability").
				Set(`"score_centi" = ?`, 990).Set(`"severity" = ?`, "critical").
				Where(`"identifier" = ?`, issue).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		r.CurlMovedTo(t, "8.6.0")

		code, body, out := reaffirmingMany(t, r, "triager", absent, unreachable)
		if code != http.StatusCreated {
			t.Fatalf("re-affirming the selection answered %d: %s", code, body)
		}
		if len(out.Decisions) != 2 {
			t.Fatalf("re-affirming two decisions answered %d: %s", len(out.Decisions), body)
		}
		seen := map[int64]bool{}
		for _, one := range out.Decisions {
			seen[one.PreviousDecisionID] = true
			switch one.PreviousDecisionID {
			case absent:
				if one.Waiting {
					t.Error("a decision that the code is absent waits after a severity rise")
				}
			case unreachable:
				if !one.Waiting {
					t.Error("a decision that the code is unreachable stood after a severity rise")
				}
			}
		}
		if !seen[absent] || !seen[unreachable] {
			t.Errorf("the answer does not name both decisions it replaced: %s", body)
		}
	})
}

func TestReAffirmingManyRefusesADecisionSomebodyElseMade(t *testing.T) {
	// Re-affirming is the proposer's right. The refusal names the issues, so
	// they can be taken out of the selection.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		one := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		two := r.AgreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.CurlMovedTo(t, "8.6.0")

		code, body, _ := reaffirmingMany(t, r, "wide-triager", one, two)
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("somebody else re-affirming answered %d: %s", code, body)
		}
		if !strings.Contains(body, "CVE-2026-CURL1") || !strings.Contains(body, "CVE-2026-CURL2") {
			t.Errorf("the refusal does not name the issues: %s", body)
		}
		written, err := r.DB.DB.NewSelect().Table("decision_occurrence").
			Where(`"state" <> ?`, "lapsed").Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if written != 0 {
			t.Errorf("a refused act left %d rows written", written)
		}
		// And nothing of theirs is on the other person's list.
		if listed := toReaffirm(t, r, "wide-triager"); len(listed) != 0 {
			t.Errorf("somebody else's lapsed decisions are listed as theirs to re-affirm: %v", listed)
		}
	})
}

func TestReAffirmingManyReachesOnlyWhatNothingReplaced(t *testing.T) {
	// A decision re-made after one bump lapses at the next, beside the decision it
	// re-made. The later one is what the occurrence last said: the earlier is not
	// listed, and naming it answers as a decision that is not there.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		one := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		two := r.AgreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.CurlMovedTo(t, "8.6.0")
		code, body, first := reaffirmingMany(t, r, "triager", one, two)
		if code != http.StatusCreated {
			t.Fatalf("the first re-affirmation answered %d: %s", code, body)
		}
		r.CurlMovedTo(t, "8.7.0")

		made := map[int64]bool{}
		var again []int64
		for _, each := range first.Decisions {
			made[each.DecisionID] = true
			again = append(again, each.DecisionID)
		}
		listed := toReaffirm(t, r, "triager")
		if len(listed) != 2 {
			t.Fatalf("%d decisions are listed to re-affirm, want the two latest", len(listed))
		}
		var counted struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", "/v1/to-reaffirm", &counted)
		if counted.Total != 2 {
			t.Errorf("the list counts %d decisions to re-affirm, want the two latest", counted.Total)
		}
		for _, each := range listed {
			if !made[each.Decision.ID] {
				t.Errorf("decision %d is listed, which a later decision replaced", each.Decision.ID)
			}
		}
		if code, body, _ := reaffirmingMany(t, r, "triager", one); code != http.StatusNotFound {
			t.Errorf("re-affirming a replaced decision answered %d: %s", code, body)
		}
		if code, body, _ := reaffirmingMany(t, r, "triager", again...); code != http.StatusCreated {
			t.Fatalf("the second re-affirmation answered %d: %s", code, body)
		}
	})
}

func TestReAffirmingManyIsBoundedOverTheWholeAct(t *testing.T) {
	// Bound what is written. Each decision here is two occurrences, inside a cap of
	// three; the act is four.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		one := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		two := r.AgreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.CurlMovedTo(t, "8.6.0")
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.write-ceiling",
			`{"value":"3"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}

		code, body, _ := reaffirmingMany(t, r, "triager", one, two)
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("an act past the cap answered %d: %s", code, body)
		}
		if !strings.Contains(body, "that is 4 findings") {
			t.Errorf("the refusal does not count the whole act: %s", body)
		}
	})
}

func TestADecisionLapsesWhenItsIssueIsRatedWorseHere(t *testing.T) {
	// A decision that something does not matter much is not a decision about
	// what it has become (REQ-25). Rating an issue into a higher band lapses a
	// decision a severity bears on, lists it as the proposer's to re-affirm, and
	// tells them; a decision that the code is absent holds at any severity.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		unreachable := r.AgreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		absent := r.AgreedAcrossTheFold(t, "CVE-2026-CURL3", "vulnerable_code_not_present")

		for _, issue := range []string{"CVE-2026-CURL2", "CVE-2026-CURL3"} {
			rated := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
				"/v1/products/mine/issues/"+issue+"/assessment",
				`{"severity":"critical","reasoning":"Reachable from the network here."}`)
			if rated.Code >= 300 {
				t.Fatalf("rating %s answered %d: %s", issue, rated.Code, rated.Body.String())
			}
		}

		states := map[int64]string{}
		for _, decision := range []int64{unreachable, absent} {
			var state string
			if err := r.DB.DB.NewSelect().Table("decision_occurrence").Column("state").
				Where(`"decision_id" = ?`, decision).Limit(1).Scan(t.Context(), &state); err != nil {
				t.Fatal(err)
			}
			states[decision] = state
		}
		if states[unreachable] != "lapsed" {
			t.Errorf("a decision that nothing reaches the code is %q after it was rated worse",
				states[unreachable])
		}
		if states[absent] != "approved" {
			t.Errorf("a decision that the code is absent is %q after it was rated worse",
				states[absent])
		}

		listed := toReaffirm(t, r, "triager")
		if len(listed) != 1 || listed[0].Decision.ID != unreachable {
			t.Fatalf("listed to re-affirm: %+v, want the one decision a severity bears on", listed)
		}
		if !listed[0].RatedWorse || listed[0].CodeMoved || listed[0].Now != "critical" {
			t.Errorf("the listing says %+v, want rated worse to critical and the code unmoved",
				listed[0])
		}
		if told := r.Alerts(t, "triager", "decision-lapsed"); len(told) == 0 {
			t.Error("the proposer was not told their decision lapsed")
		}

		// Re-affirming it goes to a second person: the rating is above what
		// was agreed to.
		code, body, out := reaffirmingMany(t, r, "triager", unreachable)
		if code != http.StatusCreated {
			t.Fatalf("re-affirming answered %d: %s", code, body)
		}
		if len(out.Decisions) != 1 || !out.Decisions[0].Waiting {
			t.Errorf("a decision re-affirmed after a rise stood without a second person: %s", body)
		}
	})
}

func TestALapsedDecisionInAProductYouCannotSeeAnswersLikeOneThatIsNotThere(t *testing.T) {
	// Authorized before anything is said about who made it (REQ-42). Naming a
	// lapsed decision elsewhere and naming one that does not exist answer alike;
	// otherwise the refusal names the issues, and walking decision identifiers is
	// a directory of what every product has dismissed.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.Scanned(t)
		r.AlsoScannedInto(t, "theirs", "master", "mellanox")
		theirs, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		person, err := r.Rights.Ensure(ctx, "private-triage", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Rights.GrantRole(ctx, person.ID, theirs.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		made := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/theirs/branches-and-tags/master/variants/mellanox"+
				"/findings/CVE-2026-9999/components/libnl-3-200/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"Not compiled into that build."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding in the other product answered %d: %s", made.Code, made.Body.String())
		}
		var their struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &their); err != nil {
			t.Fatal(err)
		}
		if _, err := r.DB.DB.NewUpdate().Table("decision_occurrence").
			Set(`"state" = ?`, "lapsed").Set(`"ended_at" = ?`, time.Now().UTC()).
			Set(`"live_key" = NULL`).
			Where(`"decision_id" = ?`, their.DecisionID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// A triager of another product, and somebody who only reads this one.
		for _, who := range []string{"triager", "reader"} {
			code, invisible, _ := reaffirmingMany(t, r, who, their.DecisionID)
			absentCode, absent, _ := reaffirmingMany(t, r, who, 999999)
			if code != absentCode || invisible != absent {
				t.Errorf("as %s, a lapsed decision elsewhere answered %d %s and a missing one %d %s",
					who, code, invisible, absentCode, absent)
			}
			if code != http.StatusNotFound || strings.Contains(invisible, "CVE-2026-9999") {
				t.Errorf("as %s, the refusal answered %d and named: %s", who, code, invisible)
			}
		}
	})
}

func TestAgreeingARatingThatRaisesTheOneInForceLapsesADecision(t *testing.T) {
	// A word below the published one is milder and waits for a second person,
	// and can still be above the published score a decision was made against.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if _, err := r.DB.DB.NewUpdate().Table("vulnerability").Set(`"score_centi" = ?`, 500).
			Where(`"identifier" = ?`, "CVE-2026-CURL1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		decision := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		r.Rated(t, "high")
		if state := r.StateOfDecision(t, decision); state != "lapsed" {
			t.Errorf("agreeing a rating from medium to high left the decision %q", state)
		}
	})
}

func TestWithdrawingAMilderRatingLapsesADecisionMadeUnderIt(t *testing.T) {
	// The published rating back in force can be worse than the one taken back.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		rating := r.Rated(t, "low")
		decision := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		if state := r.StateOfDecision(t, decision); state != "approved" {
			t.Fatalf("the decision is %q before anything moved", state)
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodDelete,
			fmt.Sprintf("/v1/assessments/%d", rating), ""); got.Code >= 300 {
			t.Fatalf("withdrawing the rating answered %d: %s", got.Code, got.Body.String())
		}
		if state := r.StateOfDecision(t, decision); state != "lapsed" {
			t.Errorf("putting critical back in force left a decision made under low %q", state)
		}
	})
}

func TestReAffirmingAPromiseTakesNoCap(t *testing.T) {
	// The next scan re-checks every row a promise names, so it is the one bulk
	// write the cap does not reach (REQ-27), in one act over many decisions as in
	// one over one.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/components/libcurl4t64/upgrade",
			`{"to":"8.5.0-1","by":"`+httpapitest.AheadOfUs+`","reasoning":"Taking the 8.5.0 bump.",`+
				`"builds":[{"branch_or_tag":"master","variant":"broadcom"}]}`); got.Code != http.StatusCreated {
			t.Fatalf("declaring answered %d: %s", got.Code, got.Body.String())
		}
		var promise int64
		if err := r.DB.DB.NewSelect().TableExpr(`"decision" AS "cl"`).ColumnExpr(`"cl"."id"`).
			Where(`"cl"."outcome" = ?`, "upgrade-needed").Limit(1).Scan(t.Context(), &promise); err != nil {
			t.Fatal(err)
		}
		r.CurlMovedTo(t, "8.4.1")
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.write-ceiling",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}
		code, body, out := reaffirmingMany(t, r, "triager", promise)
		if code != http.StatusCreated {
			t.Fatalf("re-affirming a promise past the cap answered %d: %s", code, body)
		}
		if len(out.Decisions) != 1 || len(out.Decisions[0].DecisionOccurrences) < 2 {
			t.Errorf("the promise was re-made as %s, want every occurrence past a cap of one", body)
		}
	})
}

func TestReAffirmingTakesTheLargerLimitOnlyWhereNothingGoesBackToAnApprover(t *testing.T) {
	// Two issues, a reviewer's limit of one and a re-confirmation limit of
	// two. Where both decisions stand on their earlier agreement the act passes;
	// the test below has one go back to an approver, which makes the whole act
	// a review.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		one := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		two := r.AgreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.CurlMovedTo(t, "8.6.0")
		r.LimitsOf(t, "1", "2")
		if code, body, _ := reaffirmingMany(t, r, "triager", one, two); code !=
			http.StatusCreated {
			t.Errorf("re-confirming two agreed issues under a limit of two answered %d: %s",
				code, body)
		}
	})
}

func TestReAffirmingTakesTheReviewersLimitWhereAnyDecisionGoesBack(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		absent := r.AgreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		unreachable := r.AgreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		if _, err := r.DB.DB.NewUpdate().Table("vulnerability").
			Set(`"score_centi" = ?`, 990).Set(`"severity" = ?`, "critical").
			Where(`"identifier" = ?`, "CVE-2026-CURL2").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		r.CurlMovedTo(t, "8.6.0")
		r.LimitsOf(t, "1", "2")
		code, body, _ := reaffirmingMany(t, r, "triager", absent, unreachable)
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, "that is 2 issues") {
			t.Errorf("an act with a decision going back to an approver answered %d: %s", code, body)
		}
	})
}

// A dated outcome re-affirmed at an occurrence in a tag build is refused, as making
// it there is.
//
// A tag is a release built once. A deferral or a promise to patch dated
// against one is a promise nothing can keep, and deciding one there answers
// 422. Re-affirming at a single occurrence says whether the occurrence sits in a tag,
// so the same refusal applies there.
func TestReAffirmingADatedOutcomeOnATagIsRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		occurrence := r.Scanned(t)
		r.AgreedAt(t, occurrence, `{"outcome":"deferred","deferred_until":"2030-01-01",`+
			`"reasoning":"Held until the next point release."}`)
		var previous int64
		if err := r.DB.DB.NewSelect().Table("decision_occurrence").ColumnExpr(`MAX("id")`).
			Scan(ctx, &previous); err != nil {
			t.Fatal(err)
		}

		// The component moves, which lapses the deferral, and the release it
		// sits in is a tag.
		if _, err := r.DB.DB.NewUpdate().Table("component").
			Set(`"version" = ?`, "3.8.0-1").Set(`"upstream_version" = ?`, "3.8.0").
			Where(`"name" = ?`, "libnl-3-200").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		var buildIDs []int64
		if err := r.DB.DB.NewSelect().TableExpr(`"build" AS "t"`).
			ColumnExpr(`"t"."id"`).Scan(ctx, &buildIDs); err != nil {
			t.Fatal(err)
		}
		for _, build := range buildIDs {
			if _, err := triage.NewStore(r.DB.DB).Lapse(ctx, build); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.DB.DB.NewUpdate().Table("branch_or_tag").
			Set(`"kind" = ?`, catalog.Tag).Where(`"name" = ?`, "master").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/findings/CVE-2026-9999/occurrences/"+
				occurrence+"/decision/reaffirmation",
			fmt.Sprintf(`{"previous":%d,"reasoning":"Still true."}`, previous))
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("re-affirming a deferral in a tag build answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}
