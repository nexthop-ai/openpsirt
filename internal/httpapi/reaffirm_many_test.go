// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// agreedAcrossTheFold claims one issue over the curl fold with the reason
// given, has it agreed to, and answers with the claim.
func (r *reach) agreedAcrossTheFold(t *testing.T, issue, justification string) int64 {
	t.Helper()
	decided := asPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/streams/master/variants/broadcom/components/libcurl4t64/decisions",
		fmt.Sprintf(`{"vulnerabilities":[%q],"outcome":"not-applicable",`+
			`"justification":%q,"selected_by":"the transfer path",`+
			`"reasoning":"Judged at 8.4.0."}`, issue, justification))
	if decided.Code != http.StatusCreated {
		t.Fatalf("deciding answered %d: %s", decided.Code, decided.Body.String())
	}
	var made struct {
		ClaimID int64 `json:"claim_id"`
	}
	if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
		t.Fatal(err)
	}
	r.agreed(t, made.ClaimID)
	return made.ClaimID
}

// agreed has the reviewer agree to a claim.
func (r *reach) agreed(t *testing.T, claim int64) {
	t.Helper()
	if ok := asPerson(t, r, "reviewer", http.MethodPost,
		fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
		t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
	}
}

// curlMovedTo moves curl to a new upstream version and sweeps every build, which
// is what lapses the decisions made about the old one.
func (r *reach) curlMovedTo(t *testing.T, upstream string) {
	t.Helper()
	ctx := t.Context()
	if _, err := r.db.DB.NewUpdate().Table("component").
		Set("version = ?", upstream+"-1").Set("upstream_version = ?", upstream).
		Where("name LIKE ?", "%curl%").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var targets []int64
	if err := r.db.DB.NewSelect().TableExpr(`"target" AS "t"`).
		ColumnExpr("t.id").Scan(ctx, &targets); err != nil {
		t.Fatal(err)
	}
	store := triage.NewStore(r.db.DB)
	for _, target := range targets {
		if _, err := store.Lapse(ctx, target); err != nil {
			t.Fatal(err)
		}
	}
}

// reaffirmedMany is the answer to one act over many claims.
type reaffirmedMany struct {
	Claims []struct {
		PreviousClaimID int64   `json:"previous_claim_id"`
		ClaimID         int64   `json:"claim_id"`
		Decisions       []int64 `json:"decisions"`
		Waiting         bool    `json:"waiting"`
	} `json:"claims"`
}

func reaffirmingMany(t *testing.T, r *reach, who string, claims ...int64) (int, string, reaffirmedMany) {
	t.Helper()
	named := make([]string, 0, len(claims))
	for _, id := range claims {
		named = append(named, fmt.Sprint(id))
	}
	got := asPerson(t, r, who, http.MethodPost, "/v1/reaffirmations",
		`{"reasoning":"Checked the changelog; none of these subsystems moved.",`+
			`"claims":[`+strings.Join(named, ",")+`]}`)
	var out reaffirmedMany
	if got.Code == http.StatusCreated {
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return got.Code, got.Body.String(), out
}

// toReaffirm reads the list of lapsed claims a person has to re-affirm.
func toReaffirm(t *testing.T, r *reach, who string) (items []struct {
	Claim struct {
		ID int64 `json:"id"`
	} `json:"claim"`
	CodeMoved  bool   `json:"code_moved"`
	RatedWorse bool   `json:"rated_worse"`
	Was        string `json:"was"`
	Now        string `json:"now"`
	Places     int    `json:"places"`
}) {
	t.Helper()
	var page struct {
		Items []struct {
			Claim struct {
				ID int64 `json:"id"`
			} `json:"claim"`
			CodeMoved  bool   `json:"code_moved"`
			RatedWorse bool   `json:"rated_worse"`
			Was        string `json:"was"`
			Now        string `json:"now"`
			Places     int    `json:"places"`
		} `json:"items"`
	}
	read(t, r, who, "/v1/to-reaffirm", &page)
	return page.Items
}

func TestOneActReAffirmsSeveralLapsedClaims(t *testing.T) {
	// A version bump on a large component lapses many claims at once, and each
	// is a separate claim with its own outcome and justification. One act
	// re-makes all of them under one reason, each keeping what it said.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		absent := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		unreachable := r.agreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		r.curlMovedTo(t, "8.6.0")

		code, body, out := reaffirmingMany(t, r, "triager", absent, unreachable)
		if code != http.StatusCreated {
			t.Fatalf("re-affirming the selection answered %d: %s", code, body)
		}
		if len(out.Claims) != 2 {
			t.Fatalf("the act re-made %d claims, want the two behind the selection: %s",
				len(out.Claims), body)
		}
		for _, one := range out.Claims {
			if one.PreviousClaimID != absent && one.PreviousClaimID != unreachable {
				t.Errorf("the act re-made claim %d, which nothing selected covers",
					one.PreviousClaimID)
			}
			if len(one.Decisions) != 2 {
				t.Errorf("claim %d was re-made at %d places, want both of the fold",
					one.PreviousClaimID, len(one.Decisions))
			}
			if one.Waiting {
				t.Errorf("claim %d waits for a second person with nothing changed",
					one.PreviousClaimID)
			}
			// Each keeps its own justification: the reason is shared and the
			// argument is not.
			var was, now string
			if err := r.db.DB.NewSelect().Table("claim").Column("justification").
				Where("id = ?", one.PreviousClaimID).Scan(t.Context(), &was); err != nil {
				t.Fatal(err)
			}
			if err := r.db.DB.NewSelect().Table("claim").Column("justification").
				Where("id = ?", one.ClaimID).Scan(t.Context(), &now); err != nil {
				t.Fatal(err)
			}
			if now != was {
				t.Errorf("claim %d was re-made as %q, want its own %q",
					one.PreviousClaimID, now, was)
			}
		}
	})
}

func TestASeverityRiseSendsBackOnlyTheClaimItBearsOn(t *testing.T) {
	// Each claim carries its own earlier agreement, so one that needs a second
	// look says nothing about the others. A rise bears on a claim that nothing
	// an attacker controls reaches the code, and not on one that the code is
	// absent.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		absent := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		unreachable := r.agreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		for _, issue := range []string{"CVE-2026-CURL1", "CVE-2026-CURL2"} {
			if _, err := r.db.DB.NewUpdate().Table("vulnerability").
				Set("score_centi = ?", 990).Set("severity = ?", "critical").
				Where("identifier = ?", issue).Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		r.curlMovedTo(t, "8.6.0")

		code, body, out := reaffirmingMany(t, r, "triager", absent, unreachable)
		if code != http.StatusCreated {
			t.Fatalf("re-affirming the selection answered %d: %s", code, body)
		}
		for _, one := range out.Claims {
			switch one.PreviousClaimID {
			case absent:
				if one.Waiting {
					t.Error("a claim that the code is absent waits after a severity rise")
				}
			case unreachable:
				if !one.Waiting {
					t.Error("a claim that the code is unreachable stood after a severity rise")
				}
			}
		}
	})
}

func TestReAffirmingManyRefusesAClaimSomebodyElseMade(t *testing.T) {
	// Re-affirming is the claimant's right. The refusal names the issues, so
	// they can be taken out of the selection.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		one := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		two := r.agreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.curlMovedTo(t, "8.6.0")

		code, body, _ := reaffirmingMany(t, r, "wide-triager", one, two)
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("somebody else re-affirming answered %d: %s", code, body)
		}
		if !strings.Contains(body, "CVE-2026-CURL1") || !strings.Contains(body, "CVE-2026-CURL2") {
			t.Errorf("the refusal does not name the issues: %s", body)
		}
		written, err := r.db.DB.NewSelect().Table("decision").
			Where("state <> ?", "lapsed").Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if written != 0 {
			t.Errorf("a refused act left %d decisions written", written)
		}
		// And nothing of theirs is on the other person's list.
		if listed := toReaffirm(t, r, "wide-triager"); len(listed) != 0 {
			t.Errorf("somebody else's lapsed claims are listed as theirs to re-affirm: %v", listed)
		}
	})
}

func TestReAffirmingManyReachesOnlyWhatNothingReplaced(t *testing.T) {
	// A claim re-made after one bump lapses at the next, beside the claim it
	// re-made. The later one is what the place last said: the earlier is not
	// listed, and naming it answers as a claim that is not there.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		one := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		two := r.agreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.curlMovedTo(t, "8.6.0")
		code, body, first := reaffirmingMany(t, r, "triager", one, two)
		if code != http.StatusCreated {
			t.Fatalf("the first re-affirmation answered %d: %s", code, body)
		}
		r.curlMovedTo(t, "8.7.0")

		made := map[int64]bool{}
		var again []int64
		for _, each := range first.Claims {
			made[each.ClaimID] = true
			again = append(again, each.ClaimID)
		}
		listed := toReaffirm(t, r, "triager")
		if len(listed) != 2 {
			t.Fatalf("%d claims are listed to re-affirm, want the two latest", len(listed))
		}
		var counted struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/to-reaffirm", &counted)
		if counted.Total != 2 {
			t.Errorf("the list counts %d claims to re-affirm, want the two latest", counted.Total)
		}
		for _, each := range listed {
			if !made[each.Claim.ID] {
				t.Errorf("claim %d is listed, which a later claim replaced", each.Claim.ID)
			}
		}
		if code, body, _ := reaffirmingMany(t, r, "triager", one); code != http.StatusNotFound {
			t.Errorf("re-affirming a replaced claim answered %d: %s", code, body)
		}
		if code, body, _ := reaffirmingMany(t, r, "triager", again...); code != http.StatusCreated {
			t.Fatalf("the second re-affirmation answered %d: %s", code, body)
		}
	})
}

func TestReAffirmingManyIsBoundedOverTheWholeAct(t *testing.T) {
	// Bound what is written. Each claim here is two places, inside a cap of
	// three; the act is four.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		one := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		two := r.agreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.curlMovedTo(t, "8.6.0")
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.write-ceiling",
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

func TestAClaimLapsesWhenItsIssueIsRatedWorseHere(t *testing.T) {
	// A judgment that something does not matter much is not a judgment about
	// what it has become (REQ-25). Rating an issue into a higher band lapses a
	// claim a severity bears on, lists it as the proposer's to re-affirm, and
	// tells them; a claim that the code is absent holds at any severity.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		unreachable := r.agreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		absent := r.agreedAcrossTheFold(t, "CVE-2026-CURL3", "vulnerable_code_not_present")

		for _, issue := range []string{"CVE-2026-CURL2", "CVE-2026-CURL3"} {
			rated := asPerson(t, r, "triager", http.MethodPost,
				"/v1/products/mine/issues/"+issue+"/assessment",
				`{"severity":"critical","reasoning":"Reachable from the network here."}`)
			if rated.Code >= 300 {
				t.Fatalf("rating %s answered %d: %s", issue, rated.Code, rated.Body.String())
			}
		}

		states := map[int64]string{}
		for _, claim := range []int64{unreachable, absent} {
			var state string
			if err := r.db.DB.NewSelect().Table("decision").Column("state").
				Where("claim_id = ?", claim).Limit(1).Scan(t.Context(), &state); err != nil {
				t.Fatal(err)
			}
			states[claim] = state
		}
		if states[unreachable] != "lapsed" {
			t.Errorf("a claim that nothing reaches the code is %q after it was rated worse",
				states[unreachable])
		}
		if states[absent] != "approved" {
			t.Errorf("a claim that the code is absent is %q after it was rated worse",
				states[absent])
		}

		listed := toReaffirm(t, r, "triager")
		if len(listed) != 1 || listed[0].Claim.ID != unreachable {
			t.Fatalf("listed to re-affirm: %+v, want the one claim a severity bears on", listed)
		}
		if !listed[0].RatedWorse || listed[0].CodeMoved || listed[0].Now != "critical" {
			t.Errorf("the listing says %+v, want rated worse to critical and the code unmoved",
				listed[0])
		}
		if told := r.alerts(t, "triager", "claim-lapsed"); len(told) == 0 {
			t.Error("the proposer was not told their claim lapsed")
		}

		// Re-affirming it goes to a second person: the rating is above what
		// was agreed to.
		code, body, out := reaffirmingMany(t, r, "triager", unreachable)
		if code != http.StatusCreated {
			t.Fatalf("re-affirming answered %d: %s", code, body)
		}
		if len(out.Claims) != 1 || !out.Claims[0].Waiting {
			t.Errorf("a claim re-affirmed after a rise stood without a second person: %s", body)
		}
	})
}

func TestALapsedClaimInAProductYouCannotSeeAnswersLikeOneThatIsNotThere(t *testing.T) {
	// Authorized before anything is said about who made it (REQ-42). Naming a
	// lapsed claim elsewhere and naming one that does not exist answer alike;
	// otherwise the refusal names the issues, and walking claim identifiers is
	// a directory of what every product has dismissed.
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scanned(t)
		r.alsoScannedInto(t, "theirs", "master", "mellanox")
		theirs, err := catalog.NewStore(r.db.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		person, err := r.rights.Ensure(ctx, "private-triage", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.rights.GrantRole(ctx, person.ID, theirs.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/theirs/streams/master/variants/mellanox"+
				"/findings/CVE-2026-9999/components/libnl-3-200/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"Not compiled into that build."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding in the other product answered %d: %s", made.Code, made.Body.String())
		}
		var their struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &their); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewUpdate().Table("decision").
			Set("state = ?", "lapsed").Set("ended_at = ?", time.Now().UTC()).
			Set("live_key = NULL").
			Where("claim_id = ?", their.ClaimID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// A triager of another product, and somebody who only reads this one.
		for _, who := range []string{"triager", "reader"} {
			code, invisible, _ := reaffirmingMany(t, r, who, their.ClaimID)
			absentCode, absent, _ := reaffirmingMany(t, r, who, 999999)
			if code != absentCode || invisible != absent {
				t.Errorf("as %s, a lapsed claim elsewhere answered %d %s and a missing one %d %s",
					who, code, invisible, absentCode, absent)
			}
			if code < 400 || strings.Contains(invisible, "CVE-2026-9999") {
				t.Errorf("as %s, the refusal answered %d and named: %s", who, code, invisible)
			}
		}
	})
}

// rated records a rating of CVE-2026-CURL1 here, has the reviewer agree where it
// waits, and answers the assessment.
func (r *reach) rated(t *testing.T, severity string) int64 {
	t.Helper()
	made := asPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/issues/CVE-2026-CURL1/assessment",
		`{"severity":"`+severity+`","reasoning":"How we use it."}`)
	if made.Code != http.StatusCreated {
		t.Fatalf("rating answered %d: %s", made.Code, made.Body.String())
	}
	var claim struct {
		ID            int64 `json:"id"`
		NeedsApproval bool  `json:"needs_approval"`
	}
	if err := json.Unmarshal(made.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	if claim.NeedsApproval {
		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/assessments/%d/agreement", claim.ID), ""); ok.Code >= 300 {
			t.Fatalf("agreeing to the rating answered %d: %s", ok.Code, ok.Body.String())
		}
	}
	return claim.ID
}

// stateOfClaim reads the state of one row of a claim.
func (r *reach) stateOfClaim(t *testing.T, claim int64) string {
	t.Helper()
	var state string
	if err := r.db.DB.NewSelect().Table("decision").Column("state").
		Where("claim_id = ?", claim).Limit(1).Scan(t.Context(), &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestAgreeingARatingThatRaisesTheOneInForceLapsesAClaim(t *testing.T) {
	// A word below the published one is milder and waits for a second person,
	// and can still be above the published score a claim was made against.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		if _, err := r.db.DB.NewUpdate().Table("vulnerability").Set("score_centi = ?", 500).
			Where("identifier = ?", "CVE-2026-CURL1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		claim := r.agreedAcrossTheFold(t, "CVE-2026-CURL1",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		r.rated(t, "high")
		if state := r.stateOfClaim(t, claim); state != "lapsed" {
			t.Errorf("agreeing a rating from medium to high left the claim %q", state)
		}
	})
}

func TestWithdrawingAMilderRatingLapsesAClaimMadeUnderIt(t *testing.T) {
	// The published rating back in force can be worse than the one taken back.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		rating := r.rated(t, "low")
		claim := r.agreedAcrossTheFold(t, "CVE-2026-CURL1",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		if state := r.stateOfClaim(t, claim); state != "approved" {
			t.Fatalf("the claim is %q before anything moved", state)
		}
		if got := asPerson(t, r, "triager", http.MethodDelete,
			fmt.Sprintf("/v1/assessments/%d", rating), ""); got.Code >= 300 {
			t.Fatalf("withdrawing the rating answered %d: %s", got.Code, got.Body.String())
		}
		if state := r.stateOfClaim(t, claim); state != "lapsed" {
			t.Errorf("putting critical back in force left a claim made under low %q", state)
		}
	})
}

func TestReAffirmingAPromiseTakesNoCap(t *testing.T) {
	// The next scan re-checks every row a promise names, so it is the one bulk
	// write the cap does not reach (REQ-27), in one act over many claims as in
	// one over one.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		if got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/components/libcurl4t64/upgrade",
			`{"to":"8.5.0-1","by":"`+aheadOfUs+`","reasoning":"Taking the 8.5.0 bump.",`+
				`"builds":[{"stream":"master","variant":"broadcom"}]}`); got.Code != http.StatusCreated {
			t.Fatalf("declaring answered %d: %s", got.Code, got.Body.String())
		}
		var promise int64
		if err := r.db.DB.NewSelect().TableExpr(`"claim" AS "cl"`).ColumnExpr("cl.id").
			Where("cl.outcome = ?", "upgrade-needed").Limit(1).Scan(t.Context(), &promise); err != nil {
			t.Fatal(err)
		}
		r.curlMovedTo(t, "8.4.1")
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.write-ceiling",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}
		code, body, out := reaffirmingMany(t, r, "triager", promise)
		if code != http.StatusCreated {
			t.Fatalf("re-affirming a promise past the cap answered %d: %s", code, body)
		}
		if len(out.Claims) != 1 || len(out.Claims[0].Decisions) < 2 {
			t.Errorf("the promise was re-made as %s, want every place past a cap of one", body)
		}
	})
}

// limitsOf sets the two issue limits.
func (r *reach) limitsOf(t *testing.T, review, agreed string) {
	t.Helper()
	for key, value := range map[string]string{
		"triage.review-issues": review, "triage.agreed-issues": agreed,
	} {
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/"+key,
			`{"value":"`+value+`"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting %s answered %d: %s", key, got.Code, got.Body.String())
		}
	}
}

func TestReAffirmingTakesTheLargerLimitOnlyWhereNothingGoesBackToAnApprover(t *testing.T) {
	// Two issues, a reviewer's limit of one and a re-confirmation limit of
	// two. Where both claims stand on their earlier agreement the act passes;
	// the test below has one go back to an approver, which makes the whole act
	// a review.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		one := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		two := r.agreedAcrossTheFold(t, "CVE-2026-CURL2", "vulnerable_code_not_present")
		r.curlMovedTo(t, "8.6.0")
		r.limitsOf(t, "1", "2")
		if code, body, _ := reaffirmingMany(t, r, "triager", one, two); code !=
			http.StatusCreated {
			t.Errorf("re-confirming two agreed issues under a limit of two answered %d: %s",
				code, body)
		}
	})
}

func TestReAffirmingTakesTheReviewersLimitWhereAnyClaimGoesBack(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		absent := r.agreedAcrossTheFold(t, "CVE-2026-CURL1", "vulnerable_code_not_present")
		unreachable := r.agreedAcrossTheFold(t, "CVE-2026-CURL2",
			"vulnerable_code_cannot_be_controlled_by_adversary")
		if _, err := r.db.DB.NewUpdate().Table("vulnerability").
			Set("score_centi = ?", 990).Set("severity = ?", "critical").
			Where("identifier = ?", "CVE-2026-CURL2").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		r.curlMovedTo(t, "8.6.0")
		r.limitsOf(t, "1", "2")
		code, body, _ := reaffirmingMany(t, r, "triager", absent, unreachable)
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, "that is 2 issues") {
			t.Errorf("an act with a claim going back to an approver answered %d: %s", code, body)
		}
	})
}
