package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnUpgradeIsHandedToWhoeverCarriesIt(t *testing.T) {
	// The owner's ask, and one column for a party: moving a package is
	// work a queue tracks rather than a judgment one person makes, so a
	// team is a perfectly good holder of an upgrade — often the right one.
	//
	// Recorded in the same act as the promise, because a promise nobody is
	// carrying and a holder with no promise are both things somebody has to
	// go back and fix.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"platform","display_name":"Platform","members":["triager"]}`); made.Code >= 300 {
			t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
		}
		const at = "/v1/products/mine/components/libcurl4t64/upgrade"
		plan := func(who, holder string) *httptest.ResponseRecorder {
			return asPerson(t, r, who, http.MethodPost, at,
				`{"to":"8.5.0-1","by":"2026-09-08",`+
					`"reasoning":"Taking the 8.5.0 bump in the next build.",`+
					holder+
					`"builds":[{"stream":"master","variant":"broadcom"}]}`)
		}

		// Naming both is naming nobody: work is held by one party.
		if got := plan("assigner", `"person":"triager","team":"platform",`); got.Code < 400 {
			t.Errorf("naming a person and a team answered %d", got.Code)
		}
		// A team nobody declared is refused rather than quietly ignored, or
		// the promise lands with a holder somebody thinks they set.
		if got := plan("assigner", `"team":"not-a-team",`); got.Code < 400 {
			t.Errorf("an unknown team answered %d", got.Code)
		}
		// Giving work away needs the right that names it. A triager
		// may take what nobody owns and hand back their own.
		if got := plan("triager", `"team":"platform",`); got.Code < 400 {
			t.Errorf("somebody who may not dispatch handed an upgrade to a team: %d", got.Code)
		}

		got := plan("assigner", `"team":"platform",`)
		if got.Code != http.StatusCreated {
			t.Fatalf("handing the upgrade to a team answered %d: %s", got.Code, got.Body.String())
		}
		var done struct {
			Decisions int `json:"decisions"`
			Held      int `json:"held"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		if done.Held == 0 {
			t.Fatalf("the promise was recorded and nothing was handed over: %+v", done)
		}

		// And the plan says who is carrying it, which is what a lapsed one
		// comes back to.
		var waiting struct {
			Items []struct {
				HeldBy string `json:"held_by"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom/pending-upgrades",
			&waiting)
		if len(waiting.Items) != 1 || waiting.Items[0].HeldBy != "platform" {
			t.Errorf("the plan says it is carried by %+v, want the team", waiting.Items)
		}
	})
}

func TestTheByComponentViewSaysWhatItsWeightIsMadeOf(t *testing.T) {
	// Ranking by count alone answers this view's own question backwards: a
	// package with forty-four issues outranks one with three criticals, and
	// the count beside it says nothing about which.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		const at = "/v1/products/mine/findings/components"
		var page struct {
			Items []struct {
				Component  string         `json:"component"`
				Issues     int            `json:"issues"`
				Worst      string         `json:"worst"`
				BySeverity map[string]int `json:"by_severity"`
			} `json:"items"`
		}
		read(t, r, "triager", at, &page)
		if len(page.Items) != 1 {
			t.Fatalf("%d components: %+v", len(page.Items), page.Items)
		}
		one := page.Items[0]
		// One high and one low at the same package: the split says so and the
		// worst is the high.
		if one.Worst != "high" {
			t.Errorf("the worst of a high and a low reads as %q", one.Worst)
		}
		if one.BySeverity["high"] != 1 || one.BySeverity["low"] != 1 {
			t.Errorf("the split is %+v, want one of each", one.BySeverity)
		}
		// The parts sum to the whole: both are counted as distinct issues,
		// like the number beside them.
		sum := 0
		for _, n := range one.BySeverity {
			sum += n
		}
		if sum != one.Issues {
			t.Errorf("the split sums to %d and the count says %d", sum, one.Issues)
		}

		// And asking for the worst first is answered rather than ignored.
		read(t, r, "triager", at+"?sort=severity", &page)
		if len(page.Items) != 1 {
			t.Errorf("asking for the worst first returned %+v", page.Items)
		}
	})
}
