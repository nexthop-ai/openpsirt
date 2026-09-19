package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// decide records one judgment about the scanned finding and returns whether
// the claim was recorded as waiting on a second person.
func decideOn(t *testing.T, r *reach, place, body string) bool {
	t.Helper()
	at := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
		"/findings/CVE-2026-9999/places/%s/decision", place)
	got := asPerson(t, r, "triager", http.MethodPost, at, body)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording the promise answered %d: %s", got.Code, got.Body.String())
	}
	var wrote struct {
		NeedsApproval bool `json:"needs_approval"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &wrote); err != nil {
		t.Fatal(err)
	}
	return wrote.NeedsApproval
}

// deadlines gives the scanned finding a deadline, which is what a promise to
// act is measured against.
func deadlines(t *testing.T, r *reach) {
	t.Helper()
	if _, err := finding.NewStore(r.db.DB).Recompute(t.Context(), finding.Windows{
		Exploited: 12 * time.Hour, Critical: 24 * time.Hour, High: 48 * time.Hour,
		Medium: 72 * time.Hour, Low: 96 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
}

// A promise to act past the deadline the finding already has defers the worst
// thing it covers, so a second person agrees. Recorded from a finding the gate
// had no deadline to measure against at all: the place resolution never
// carried one, so every backport recorded here stood the moment it was
// written, suppressed the finding, and appeared in no review queue.
func TestAPromisePastTheDeadlineTheFindingHasIsGated(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		deadlines(t, r)

		// The finding is high, so its deadline is two days out. This lands a
		// month past it.
		past := time.Now().UTC().AddDate(0, 0, 30).Format(time.DateOnly)
		if !decideOn(t, r, place, `{"outcome":"patch-needed","committed_to":"`+past+`",`+
			`"reasoning":"Backport is queued behind the release."}`) {
			t.Error("a promise a month past the finding's deadline was recorded as needing nobody")
		}

		// And it is waiting rather than in force: a claim that hides risk and
		// has not been agreed to suppresses nothing.
		var page struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?state=waiting", &page)
		if page.Total != 1 {
			t.Errorf("the promise is not waiting on anybody: %d rows in the waiting state", page.Total)
		}
	})
}

// Inside that deadline it hides nothing the policy did not already allow, and
// gating it would put the most routine act of all through the review queue.
func TestAPromiseInsideTheDeadlineTheFindingHasStandsOnItsOwn(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		deadlines(t, r)

		// The high window is two days, so tomorrow is inside it.
		soon := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
		if decideOn(t, r, place, `{"outcome":"patch-needed","committed_to":"`+soon+`",`+
			`"reasoning":"Backport lands in tomorrow's build."}`) {
			t.Error("a promise inside the finding's deadline was put through the queue")
		}
	})
}

// With nothing the act covers carrying a deadline, there is no date the
// promise can be inside, so the exemption has nothing to measure against and a
// second person agrees. A product below its own triage line was the one place
// a promise could hide a finding for years on one signature.
func TestAPromiseCoveringWorkWithNoDeadlineIsGated(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		// The product only triages criticals, and the finding is high, so
		// the clock is taken off it and there is nothing to be past.
		located, err := catalog.NewStore(r.db.DB).Locate(t.Context(), "mine", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		if err := catalog.NewStore(r.db.DB).SetTriageFloor(t.Context(),
			located.ProductID, "critical"); err != nil {
			t.Fatal(err)
		}
		deadlines(t, r)

		past := time.Now().UTC().AddDate(0, 0, 30).Format(time.DateOnly)
		if !decideOn(t, r, place, `{"outcome":"patch-needed","committed_to":"`+past+`",`+
			`"reasoning":"Backport is queued behind the release."}`) {
			t.Error("a promise covering work with no deadline was recorded as needing nobody")
		}
	})
}
