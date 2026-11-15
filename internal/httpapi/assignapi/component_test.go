// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAnUpgradeIsHandedToWhoeverCarriesIt(t *testing.T) {
	// One column for a party: moving a package is work a queue tracks
	// rather than a decision one person makes, so a team is a perfectly
	// good holder of an upgrade — often the right one.
	//
	// Recorded in the same act as the promise, because a promise nobody is
	// carrying and a holder with no promise are both things somebody has to
	// go back and fix.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"platform","display_name":"Platform","members":["triager"]}`); made.Code >= 300 {
			t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
		}
		const at = "/v1/products/mine/components/libcurl4t64/upgrade"
		plan := func(who, holder string) *httptest.ResponseRecorder {
			return httpapitest.AsPerson(t, r, who, http.MethodPost, at,
				`{"to":"8.5.0-1","by":"`+httpapitest.AheadOfUs+`",`+
					`"reasoning":"Taking the 8.5.0 bump in the next build.",`+
					holder+
					`"builds":[{"branch_or_tag":"master","variant":"broadcom"}]}`)
		}

		// Naming both is naming nobody: work is held by one party.
		httpapitest.RefusedWith(t, plan("assigner", `"person":"triager","team":"platform",`),
			http.StatusUnprocessableEntity)
		// A team nobody declared is refused rather than quietly ignored, or
		// the promise lands with a holder somebody thinks they set.
		httpapitest.RefusedWith(t, plan("assigner", `"team":"not-a-team",`), http.StatusNotFound)
		// Giving work away needs the right that names it. A triager
		// may take what nobody owns and hand back their own.
		httpapitest.RefusedWith(t, plan("triager", `"team":"platform",`), http.StatusUnprocessableEntity)

		got := plan("assigner", `"team":"platform",`)
		if got.Code != http.StatusCreated {
			t.Fatalf("handing the upgrade to a team answered %d: %s", got.Code, got.Body.String())
		}
		var done struct {
			Occurrences int `json:"occurrences"`
			Held        int `json:"held"`
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
				HeldBy     string `json:"held_by"`
				HeldByName string `json:"held_by_name"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom/planned-upgrades",
			&waiting)
		if len(waiting.Items) != 1 || waiting.Items[0].HeldBy != "platform" || waiting.Items[0].HeldByName != "Platform" {
			t.Errorf("the plan says it is carried by %+v, want the team's name with its display name beside it",
				waiting.Items)
		}
	})
}

func TestTheByComponentViewSaysWhatItsWeightIsMadeOf(t *testing.T) {
	// Ranking by count alone answers this view's own question backwards: a
	// package with forty-four issues outranks one with three criticals, and
	// the count beside it says nothing about which.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		const at = "/v1/products/mine/findings/components"
		var page struct {
			Items []struct {
				Component  string         `json:"component"`
				Issues     int            `json:"issues"`
				Worst      string         `json:"worst"`
				BySeverity map[string]int `json:"by_severity"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", at, &page)
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

	})
}

func TestTheByComponentViewOrdersByTheWorstWhenAsked(t *testing.T) {
	// One package holds a high and a low, the other a single critical, so the
	// two orders by severity disagree about which comes first and a route
	// that drops the sort answers one of them wrongly.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		kernel := graph.Described{Purl: "pkg:deb/debian/linux-image@5.10", Name: "linux-image", Version: "5.10"}
		expat := graph.Described{Purl: "pkg:deb/debian/libexpat1@2.5.0-1", Name: "libexpat1", Version: "2.5.0-1"}
		r.Scan(t, "two-components", graph.Snapshot{
			Root:       httpapitest.SeededRoot,
			Components: []graph.Described{kernel, expat},
			Dependencies: []graph.Dependency{
				{Parent: httpapitest.SeededRoot, Child: kernel},
				{Parent: httpapitest.SeededRoot, Child: expat},
			},
		}, []finding.Reported{
			{Issue: finding.Named{Identifier: "CVE-2026-9999", Severity: "high", Score: 8.1},
				Component: kernel, FixState: finding.NoFix},
			{Issue: finding.Named{Identifier: "CVE-2026-1000", Severity: "low", Score: 3.1},
				Component: kernel, FixState: finding.NoFix},
			{Issue: finding.Named{Identifier: "CVE-2026-2000", Severity: "critical", Score: 9.8},
				Component: expat, FixState: finding.NoFix},
		})
		const at = "/v1/products/mine/findings/components"
		order := func(query string) []string {
			var page struct {
				Items []struct {
					Component string `json:"component"`
				} `json:"items"`
			}
			httpapitest.Read(t, r, "triager", at+query, &page)
			names := make([]string, 0, len(page.Items))
			for _, one := range page.Items {
				names = append(names, one.Component)
			}
			return names
		}
		if got := order("?sort=severity"); !slices.Equal(got, []string{"libexpat1", "linux-image"}) {
			t.Errorf("the worst first reads %v, want the critical's package first", got)
		}
		if got := order("?sort=severity&asc=true"); !slices.Equal(got, []string{"linux-image", "libexpat1"}) {
			t.Errorf("the least worst first reads %v, want the high's package first", got)
		}
	})
}
