// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// A team listing that is still full at the last page read is refused rather
// than cut short: a short list withdraws roles from whoever is in many teams,
// and nothing on either side could say why. The listing is read no further
// than one page past the bound, which is what tells a listing of exactly the
// bound from a longer one.
//
// Verified by replacing the refusal after the page loop with `return names,
// nil`: the sign-in then completes with every team read so far.
func TestATeamListingPastTheLastPageReadIsRefused(t *testing.T) {
	var asked atomic.Int64
	adapter := forgeAnswering(t, "ours", ana, []any{}, func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		full := make([]any, 0, teamPageSize)
		for i := range teamPageSize {
			full = append(full, map[string]any{
				"slug":         "team" + r.URL.Query().Get("page") + "-" + strconv.Itoa(i),
				"organization": map[string]any{"login": "ours"}})
		}
		writeJSON(w, full)
	})
	who, err := adapter.Complete(t.Context(), "a-code", Pending{Verifier: "v"},
		"https://here.example/back")
	if err == nil {
		t.Fatalf("a listing still full at page %d was taken as whole: %d groups",
			maxTeamPages, len(who.Groups))
	}
	if !strings.Contains(err.Error(), "pages of teams") {
		t.Errorf("the refusal does not say what it would not read: %v", err)
	}
	if n := asked.Load(); n != maxTeamPages+1 {
		t.Errorf("%d pages were asked for, want %d", n, maxTeamPages+1)
	}
}

// A listing of exactly the bound in full pages is whole: the page after it is
// empty, and every team on the pages read is kept.
func TestATeamListingOfExactlyTheBoundIsWhole(t *testing.T) {
	adapter := forgeAnswering(t, "ours", ana, []any{}, func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		full := make([]any, 0, teamPageSize)
		for i := range teamPageSize {
			if page > maxTeamPages {
				break
			}
			full = append(full, map[string]any{
				"slug":         "team" + strconv.Itoa(page) + "-" + strconv.Itoa(i),
				"organization": map[string]any{"login": "ours"}})
		}
		writeJSON(w, full)
	})
	who, err := adapter.Complete(t.Context(), "a-code", Pending{Verifier: "v"},
		"https://here.example/back")
	if err != nil {
		t.Fatalf("a listing of exactly %d full pages was refused: %v", maxTeamPages, err)
	}
	if len(who.Groups) != maxTeamPages*teamPageSize {
		t.Errorf("%d teams were kept, want %d", len(who.Groups), maxTeamPages*teamPageSize)
	}
}
