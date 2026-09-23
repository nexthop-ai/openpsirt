// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestWhoMayHoldWorkIsPeopleAndTeams(t *testing.T) {
	// Every assignee picker was fed by the mentions endpoint, which answers
	// who can already *read* a finding. That is right for offering a name
	// inside text and wrong for handing work over: a team cannot be mentioned
	// in prose and is a perfectly good holder, so no finding could be assigned
	// to a team from the interface at all.
	twoReach(t, func(t *testing.T, r *reach) {
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"platform","display_name":"Platform"}`); made.Code >= 300 {
			t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
		}

		read := func(t *testing.T, who, asked string) []map[string]any {
			t.Helper()
			got := asPerson(t, r, who, http.MethodGet,
				"/v1/products/mine/holders"+asked, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s asking answered %d: %s", who, got.Code, got.Body.String())
			}
			var body struct {
				Items []map[string]any `json:"items"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			return body.Items
		}

		items := read(t, "triager", "")
		var teams, people int
		for _, item := range items {
			switch item["kind"] {
			case "team":
				teams++
			case "person":
				people++
			default:
				t.Errorf("a holder with no kind: %v", item)
			}
		}
		if teams == 0 {
			t.Error("no team is offered, which is the whole of what this exists for")
		}
		if people == 0 {
			t.Error("no person is offered")
		}

		// Narrowed on the server, because a picker at a hundred people cannot
		// fetch them all: the limit would cut the list before the term did.
		narrowed := read(t, "triager", "?q=platf")
		if len(narrowed) != 1 || narrowed[0]["kind"] != "team" {
			t.Fatalf("narrowing to the team's name gave %d rows: %v", len(narrowed), narrowed)
		}
		if narrowed[0]["identity"] != "platform" {
			t.Errorf("the team is named %q", narrowed[0]["identity"])
		}
		// The spelling somebody typed is what comes back to be shown.
		if narrowed[0]["name"] != "Platform" {
			t.Errorf("the team shows as %q, want what was typed", narrowed[0]["name"])
		}

		// A term matching nothing is an empty list rather than everybody,
		// which is the failure a picker makes by ignoring what it cannot use.
		if none := read(t, "triager", "?q=zzzznothing"); len(none) != 0 {
			t.Errorf("a term matching nothing returned %d rows", len(none))
		}
	})
}

func TestWhoMayHoldUndisclosedWorkIsNotAnswered(t *testing.T) {
	// A request for who may hold undisclosed work is itself about undisclosed
	// work. Somebody who cannot read it is answered as though the product
	// were not there, which is what every other path does — and the
	// request is refused before any name is resolved, so it cannot be used
	// to find out who has an account.
	twoReach(t, func(t *testing.T, r *reach) {
		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/holders?visibility=private", "")
		if got.Code != http.StatusNotFound {
			t.Fatalf("somebody who may not read undisclosed work got %d: %s",
				got.Code, got.Body.String())
		}
		if strings.Contains(got.Body.String(), "private") &&
			strings.Contains(got.Body.String(), "role") {
			t.Error("the refusal says which right was missing, which is the answer itself")
		}

		// And somebody who may read it is answered.
		if ok := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/products/mine/holders?visibility=private", ""); ok.Code != http.StatusOK {
			t.Fatalf("somebody who may read undisclosed work got %d: %s",
				ok.Code, ok.Body.String())
		}
	})
}
