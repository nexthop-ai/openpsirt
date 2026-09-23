// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"testing"
)

// TestWhereTheEffortWentIsAReport is the question a planning meeting asks.
//
// Every other figure counts the backlog — what is open, what is overdue, how
// long things wait. None of them says what the quarter actually went into, and
// that is the one a manager has to answer without any of the others.
func TestWhereTheEffortWentIsAReport(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		r.claimed(t, "private-triage", "CVE-2026-1000", "linux-image", dismissal)

		spent := func(t *testing.T, query string) []struct {
			Component string `json:"component"`
			Claims    int    `json:"claims"`
			Decisions int    `json:"decisions"`
			People    int    `json:"people"`
			Dismissed int    `json:"dismissed"`
		} {
			t.Helper()
			var out struct {
				Items []struct {
					Component string `json:"component"`
					Claims    int    `json:"claims"`
					Decisions int    `json:"decisions"`
					People    int    `json:"people"`
					Dismissed int    `json:"dismissed"`
				} `json:"items"`
			}
			read(t, r, "private-triage", "/v1/effort"+query, &out)
			return out.Items
		}

		rows := spent(t, "")
		if len(rows) != 1 {
			t.Fatalf("two claims about one component report as %d rows: %+v", len(rows), rows)
		}
		one := rows[0]
		if one.Component != "linux-image" {
			t.Errorf("the work went into %q", one.Component)
		}
		// Claims and places both, because ten claims over ten places and one
		// claim over a thousand are different afternoons.
		if one.Claims != 2 || one.Decisions < 2 {
			t.Errorf("two arguments over the component report as %+v", one)
		}
		if one.People != 2 {
			t.Errorf("two people argued and the report says %d", one.People)
		}
		// And what came out of them, which is as much the answer as the
		// volume: a component that took forty arguments and dismissed forty
		// is a different quarter from one that promised forty upgrades.
		if one.Dismissed != 2 {
			t.Errorf("two dismissals report as %d", one.Dismissed)
		}

		// A period the work does not fall in says so rather than reporting
		// the lifetime figure.
		if before := spent(t, "?to=2020-01-01"); len(before) != 0 {
			t.Errorf("a period before the work reports %+v", before)
		}

		// And it takes the same scope the other reports do.
		if elsewhere := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/effort?product=theirs", ""); elsewhere.Code < 400 {
			t.Errorf("a product this reader cannot see answered %d", elsewhere.Code)
		}
		if unknown := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/effort?team=nobodys", ""); unknown.Code != http.StatusNotFound {
			t.Errorf("a team nobody declared answered %d", unknown.Code)
		}
		if mine := spent(t, "?product=mine"); len(mine) != 1 {
			t.Errorf("the product the work happened in reports %+v", mine)
		}
	})
}

// TestEffortCountsActsRatherThanRows is the unit the report is in.
//
// One claim over sixty places is one afternoon. Counted by its rows, a report
// about where the time went would measure how far a component fans out through
// an image, and the component every image vendors would be the answer every
// quarter.
func TestEffortCountsActsRatherThanRows(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedAtTwoPlaces(t)
		r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)

		var out struct {
			Items []struct {
				Claims    int `json:"claims"`
				Decisions int `json:"decisions"`
			} `json:"items"`
		}
		read(t, r, "private-triage", "/v1/effort", &out)
		if len(out.Items) != 1 {
			t.Fatalf("one argument reports as %d rows", len(out.Items))
		}
		if out.Items[0].Claims != 1 {
			t.Errorf("one argument counts as %d claims", out.Items[0].Claims)
		}
		// And the places it reached are beside it, because the two are
		// different questions and a report carrying one of them hides the
		// other.
		if out.Items[0].Decisions != 2 {
			t.Errorf("one argument over two places reached %d", out.Items[0].Decisions)
		}
	})
}
