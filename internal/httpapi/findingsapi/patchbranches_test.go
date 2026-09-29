// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestPatchBranchProgressComesInTheOrderTheRepositoriesAreVisited(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		for _, each := range []struct{ identifier, severity, repository string }{
			{"CVE-2031-0001", "low", "mild"},
			{"CVE-2031-0002", "critical", "severe"},
		} {
			interned, err := finding.NewVulnerabilities(r.DB.DB).Intern(ctx,
				[]finding.Named{{Identifier: each.identifier, Severity: each.severity}})
			if err != nil {
				t.Fatal(err)
			}
			row := &finding.Vulnerability{ID: interned[each.identifier]}
			reference := &finding.Reference{
				VulnerabilityID: row.ID, Kind: finding.Patch, URLIdentity: each.identifier,
				URL: "https://github.com/example/" + each.repository + "/commit/" + strings.Repeat("ab", 20),
			}
			if _, err := r.DB.DB.NewInsert().Model(reference).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		got := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/patch-branches?limit=200", "")
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
