// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// fixed is the obligation list as one person reads it, with the window
// counting from the fix and the releases named on the record.
type fixed struct {
	Items []struct {
		Windows []struct {
			Window struct {
				Name    string `json:"name"`
				FromFix bool   `json:"from_fix"`
			} `json:"window"`
			Started  bool   `json:"started"`
			StartsAt string `json:"starts_at"`
			EndsAt   string `json:"ends_at"`
		} `json:"windows"`
		Fixes []struct {
			ID          int64  `json:"id"`
			Release     string `json:"release"`
			ReleasedOn  string `json:"released_on"`
			NamedBy     string `json:"named_by"`
			WithdrawnAt string `json:"withdrawn_at"`
			Scanned     bool   `json:"scanned"`
			Open        bool   `json:"open"`
		} `json:"fixes"`
	} `json:"items"`
}

// A window counting from the fix has no start until a tag with a stated
// release date is named on the record, then runs from the start of that day
// and raises its alert saying so. Withdrawing the tag leaves it unstarted
// again. A branch is refused, and naming one tag twice conflicts.
func TestAWindowCountingFromTheFixRunsFromANamedTagsReleaseDate(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		ctx := t.Context()
		got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/obligation-windows",
			`{"name":"Fix available","hours":336,"from_fix":true}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("declaring a window counting from the fix answered %d: %s", got.Code, got.Body.String())
		}
		if refused := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/obligation-windows",
			`{"name":"Both","hours":24,"from":1,"from_fix":true}`); refused.Code != http.StatusUnprocessableEntity {
			t.Errorf("a window counting from a notice and the fix answered %d", refused.Code)
		}
		record := r.AttackedAt(t, time.Now().UTC().Add(-72*time.Hour))

		var seen fixed
		seen = fixed{}
		httpapitest.Read(t, r, "private-triage", "/v1/obligations", &seen)
		window := seen.Items[0].Windows[0]
		if !window.Window.FromFix || window.Started || window.StartsAt != "" {
			t.Fatalf("with no tag named the window reads %+v, want no start", window)
		}

		cat := catalog.NewStore(r.DB.DB)
		product, err := cat.ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		tag, err := cat.DeclareStream(ctx, product.ID, "v1.0.1", catalog.Tag, nil)
		if err != nil {
			t.Fatal(err)
		}
		released := time.Now().UTC().AddDate(0, 0, -2)
		y, m, d := released.Date()
		releasedOn := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
		if err := cat.SetReleasedOn(ctx, tag.ID, &releasedOn); err != nil {
			t.Fatal(err)
		}

		path := fmt.Sprintf("/v1/exploited-here/%d/fixes", record)
		if branch := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, path,
			`{"release":"master"}`); branch.Code != http.StatusUnprocessableEntity {
			t.Errorf("naming a branch answered %d", branch.Code)
		}
		named := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, path, `{"release":"v1.0.1"}`)
		if named.Code != http.StatusCreated {
			t.Fatalf("naming a tag answered %d: %s", named.Code, named.Body.String())
		}
		var fix struct {
			ID         int64  `json:"id"`
			Release    string `json:"release"`
			ReleasedOn string `json:"released_on"`
			Scanned    bool   `json:"scanned"`
		}
		if err := json.Unmarshal(named.Body.Bytes(), &fix); err != nil {
			t.Fatal(err)
		}
		if fix.Release != "v1.0.1" || fix.ReleasedOn != releasedOn.Format(time.DateOnly) || fix.Scanned {
			t.Errorf("the tag named reads %+v", fix)
		}
		if again := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost, path,
			`{"release":"V1.0.1"}`); again.Code != http.StatusConflict {
			t.Errorf("naming the tag twice answered %d", again.Code)
		}

		seen = fixed{}
		httpapitest.Read(t, r, "private-triage", "/v1/obligations", &seen)
		window = seen.Items[0].Windows[0]
		if !window.Started || window.StartsAt != releasedOn.Format(time.RFC3339) {
			t.Errorf("with a dated tag named the window reads %+v, want it started at %s", window, releasedOn)
		}
		if fixes := seen.Items[0].Fixes; len(fixes) != 1 || fixes[0].Release != "v1.0.1" ||
			fixes[0].NamedBy == "" {
			t.Errorf("the record's fix releases read %+v", fixes)
		}
		open := r.Alerts(t, "private-triage", "obligation-open")
		if len(open) != 1 || !httpapitest.Contains(open[0], "the release of the fix") {
			t.Errorf("the running windows are %v, want the one counting from the fix", open)
		}

		if gone := httpapitest.AsPerson(t, r, "private-triage", http.MethodDelete,
			fmt.Sprintf("%s/%d", path, fix.ID), ""); gone.Code != http.StatusNoContent {
			t.Fatalf("withdrawing the tag answered %d: %s", gone.Code, gone.Body.String())
		}
		if twice := httpapitest.AsPerson(t, r, "private-triage", http.MethodDelete,
			fmt.Sprintf("%s/%d", path, fix.ID), ""); twice.Code != http.StatusNotFound {
			t.Errorf("withdrawing the tag twice answered %d", twice.Code)
		}
		seen = fixed{}
		httpapitest.Read(t, r, "private-triage", "/v1/obligations", &seen)
		window = seen.Items[0].Windows[0]
		if window.Started || window.StartsAt != "" {
			t.Errorf("with the tag withdrawn the window reads %+v, want no start", window)
		}
		if fixes := seen.Items[0].Fixes; len(fixes) != 1 || fixes[0].WithdrawnAt == "" {
			t.Errorf("the withdrawn tag reads %+v, want it kept and saying so", fixes)
		}
	})
}
