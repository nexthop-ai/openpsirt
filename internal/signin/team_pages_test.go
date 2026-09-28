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
// than the bound.
//
// Verified by replacing the refusal after the page loop with `return names,
// nil`: the sign-in then completes with every team read so far.
func TestATeamListingPastTheLastPageReadIsRefused(t *testing.T) {
	var asked atomic.Int64
	adapter := forge(t, "ours", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/token"):
			writeJSON(w, map[string]any{"access_token": "a-token", "token_type": "Bearer"})
		case r.URL.Path == "/user":
			writeJSON(w, map[string]any{"login": "ana", "id": 42})
		case r.URL.Path == "/user/emails":
			writeJSON(w, []any{})
		case r.URL.Path == "/user/teams":
			asked.Add(1)
			full := make([]any, 0, teamPageSize)
			for i := range teamPageSize {
				full = append(full, map[string]any{
					"slug":         "team" + r.URL.Query().Get("page") + "-" + strconv.Itoa(i),
					"organization": map[string]any{"login": "ours"}})
			}
			writeJSON(w, full)
		default:
			http.NotFound(w, r)
		}
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
	if n := asked.Load(); n != maxTeamPages {
		t.Errorf("%d pages were asked for, want %d", n, maxTeamPages)
	}
}
