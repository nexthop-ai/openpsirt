package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
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
		// Nothing has a deadline in this fixture, so there is none to be past
		// and the promise stands — which is also the ordinary case for a
		// product below its own triage line.
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
		got := asPerson(t, r, "reader", http.MethodPost,
			"/v1/products/mine/components/linux-image/upgrade", body)
		if got.Code < 400 {
			t.Fatalf("somebody who may not triage planned an upgrade: %d", got.Code)
		}
	})
}
