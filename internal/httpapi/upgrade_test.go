package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPlanningAnUpgradeAnswersEverythingOpenOnTheComponent(t *testing.T) {
	// Coverage is the component, not a version pair. Moving to a version is a
	// claim that it answers what is open on the package — including findings
	// recorded as fixed in an earlier release of the same line — and the next
	// scan says which of that was true. Deciding it from the versions would
	// need an ordering per ecosystem this does not have.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		soon := time.Now().UTC().Add(365 * 24 * time.Hour).Format("2006-01-02")
		body := fmt.Sprintf(`{"to":"9.9.9","by":%q,
			"builds":[{"stream":"master","variant":"broadcom"}],
			"reasoning":"Moving the package rather than answering each of these."}`, soon)
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/components/linux-image/upgrade", body)
		if made.Code != http.StatusCreated {
			t.Fatalf("planning answered %d: %s", made.Code, made.Body.String())
		}
		var done struct {
			Decisions int  `json:"decisions"`
			Issues    int  `json:"issues"`
			Targets   int  `json:"targets"`
			Waiting   bool `json:"waiting"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		if done.Decisions == 0 || done.Issues == 0 {
			t.Fatalf("it recorded nothing: %+v", done)
		}
		// A date a year out is past the deadline of anything with one, so a
		// second person agrees. The response says which, rather than leaving
		// somebody to find out from the queue.
		if !done.Waiting {
			t.Error("a promise a year out was not gated")
		}
		if done.Targets == 0 {
			t.Error("nothing was recorded for the release to wait on")
		}
	})
}

func TestAPromiseInsideTheDeadlineStandsOnItsOwn(t *testing.T) {
	// The exception the deferral threshold makes for a short deferral, in
	// the shape this outcome needs: inside the window the work already
	// had, nothing is hidden for longer than the policy allowed, so gating
	// it would put the most routine act of all through the review queue.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		// A finding gets its deadline when it is first seen, and these are
		// days out, so tomorrow is inside them.
		tomorrow := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02")
		body := fmt.Sprintf(`{"to":"9.9.9","by":%q,
			"builds":[{"stream":"master","variant":"broadcom"}],
			"reasoning":"Landing in the next build."}`, tomorrow)
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/components/linux-image/upgrade", body)
		if made.Code != http.StatusCreated {
			t.Fatalf("planning answered %d: %s", made.Code, made.Body.String())
		}
		var done struct {
			Waiting bool `json:"waiting"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		if done.Waiting {
			t.Error("a promise with no deadline to be past was gated")
		}
	})
}

func TestPlanningAnUpgradeNeedsTheTriageRight(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		soon := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02")
		body := fmt.Sprintf(`{"to":"9.9.9","by":%q,
			"builds":[{"stream":"master","variant":"broadcom"}],"reasoning":"No."}`, soon)
		refusedWith(t, asPerson(t, r, "reader", http.MethodPost,
			"/v1/products/mine/components/linux-image/upgrade", body),
			http.StatusForbidden)
	})
}

// Moving the date is moving the thing the gate is about. A promise first made
// inside the deadline the work already had was recorded as needing nobody,
// and nothing recomputed that when the date changed — so the same claim could
// be pushed years out, stay in force, go on suppressing everything it covered,
// and never appear in the review queue.
func TestMovingAPromisePastTheDeadlineGatesItAgain(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		tomorrow := time.Now().UTC().Add(24 * time.Hour).Format(time.DateOnly)
		body := fmt.Sprintf(`{"to":"9.9.9","by":%q,
			"builds":[{"stream":"master","variant":"broadcom"}],
			"reasoning":"Landing in the next build."}`, tomorrow)
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/components/linux-image/upgrade", body)
		if made.Code != http.StatusCreated {
			t.Fatalf("planning answered %d: %s", made.Code, made.Body.String())
		}
		var done struct {
			ClaimID int64 `json:"claim_id"`
			Waiting bool  `json:"waiting"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		if done.Waiting {
			t.Fatalf("a promise inside the deadline was gated, so this tests nothing")
		}

		// The same promise, a year out.
		later := time.Now().UTC().Add(365 * 24 * time.Hour).Format(time.DateOnly)
		moved := asPerson(t, r, "private-triage", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/promise", done.ClaimID),
			fmt.Sprintf(`{"to":"9.9.9","by":%q,"reasoning":"Slipping to next year."}`, later))
		if moved.Code != http.StatusNoContent {
			t.Fatalf("moving the promise answered %d: %s", moved.Code, moved.Body.String())
		}

		// It is now waiting on somebody, which is what the review queue lists.
		var queue struct {
			Total int `json:"total"`
		}
		read(t, r, "reviewer", "/v1/review-queue", &queue)
		if queue.Total != 1 {
			t.Errorf("a promise moved a year out left %d claims waiting", queue.Total)
		}
	})
}

// A promise lands on a date still to come. Moving one onto a date already
// past says the work will have happened before now.
func TestAPromiseCannotBeMovedOntoADateAlreadyPast(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		tomorrow := time.Now().UTC().Add(24 * time.Hour).Format(time.DateOnly)
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/components/linux-image/upgrade",
			fmt.Sprintf(`{"to":"9.9.9","by":%q,
				"builds":[{"stream":"master","variant":"broadcom"}],
				"reasoning":"Landing in the next build."}`, tomorrow))
		if made.Code != http.StatusCreated {
			t.Fatalf("planning answered %d: %s", made.Code, made.Body.String())
		}
		var done struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		gone := time.Now().UTC().Add(-24 * time.Hour).Format(time.DateOnly)
		refusedWith(t, asPerson(t, r, "private-triage", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/promise", done.ClaimID),
			fmt.Sprintf(`{"to":"9.9.9","by":%q,"reasoning":"Backdated."}`, gone)),
			http.StatusUnprocessableEntity)
	})
}

// Every path that stores typed text runs the markdown policy before storing
// it. Re-promising reached the write through the inner revision, which did
// not, so raw HTML and remote images went into the claim's history.
func TestMovingAPromiseRunsTheMarkdownPolicyOnItsReasoning(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		tomorrow := time.Now().UTC().Add(24 * time.Hour).Format(time.DateOnly)
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/components/linux-image/upgrade",
			fmt.Sprintf(`{"to":"9.9.9","by":%q,
				"builds":[{"stream":"master","variant":"broadcom"}],
				"reasoning":"Landing in the next build."}`, tomorrow))
		if made.Code != http.StatusCreated {
			t.Fatalf("planning answered %d: %s", made.Code, made.Body.String())
		}
		var done struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		later := time.Now().UTC().Add(48 * time.Hour).Format(time.DateOnly)
		refusedWith(t, asPerson(t, r, "private-triage", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/promise", done.ClaimID),
			fmt.Sprintf(`{"to":"9.9.9","by":%q,`+
				`"reasoning":"Slipping <script>alert(1)</script>"}`, later)),
			http.StatusUnprocessableEntity)

		// And the text never reached storage. The status alone would pass with
		// the policy running after the write instead of before it, which is
		// what this route did: the re-promise reached the claim through the
		// inner revision, and that one did not check.
		var claim struct {
			Argument struct {
				Reasoning string `json:"reasoning"`
			} `json:"argument"`
		}
		read(t, r, "private-triage", fmt.Sprintf("/v1/claims/%d", done.ClaimID), &claim)
		if strings.Contains(claim.Argument.Reasoning, "<script>") {
			t.Errorf("the refused reasoning was stored anyway: %q", claim.Argument.Reasoning)
		}
	})
}
