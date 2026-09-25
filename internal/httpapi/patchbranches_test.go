// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestPatchBranchProgressComesInTheOrderTheRepositoriesAreVisited(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		for _, each := range []struct{ identifier, severity, repository string }{
			{"CVE-2031-0001", "low", "mild"},
			{"CVE-2031-0002", "critical", "severe"},
		} {
			row := &finding.Vulnerability{
				Identifier: each.identifier, IdentifierFolded: strings.ToLower(each.identifier),
				Severity: each.severity, FirstSeenAt: time.Now().UTC(),
			}
			if _, err := r.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			reference := &finding.Reference{
				VulnerabilityID: row.ID, Kind: finding.Patch, URLIdentity: each.identifier,
				URL: "https://github.com/example/" + each.repository + "/commit/" + strings.Repeat("ab", 20),
			}
			if _, err := r.db.DB.NewInsert().Model(reference).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		got := asPerson(t, r, "admin", http.MethodGet, "/v1/patch-branches?limit=200", "")
		if got.Code != http.StatusOK {
			t.Fatalf("answered %d: %s", got.Code, got.Body.String())
		}
		var body struct {
			Repositories []struct {
				URL      string `json:"url"`
				Position int    `json:"position"`
				Worst    string `json:"worst"`
				Due      int    `json:"due"`
			} `json:"repositories"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		at := map[string]int{}
		for i, each := range body.Repositories {
			switch each.URL {
			case "https://github.com/example/severe.git":
				if each.Worst != "critical" || each.Due != 1 {
					t.Errorf("the severe repository reads %+v, want one critical commit due", each)
				}
				at["severe"] = i
			case "https://github.com/example/mild.git":
				at["mild"] = i
			default:
				continue
			}
			if each.Position == 0 {
				t.Errorf("%s has no position in the order it is visited", each.URL)
			}
		}
		if len(at) != 2 {
			t.Fatalf("the report lists %v of the two repositories", at)
		}
		if at["severe"] > at["mild"] {
			t.Errorf("the repository behind the critical is listed after the low one: %v", at)
		}
	})
}
