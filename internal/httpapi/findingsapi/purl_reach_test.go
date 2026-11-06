// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// shippedAtTwoVersions is one package at two commits with an issue at each,
// the second undisclosed, and a package of a longer name beside it.
func shippedAtTwoVersions(t *testing.T, r *httpapitest.Reach) {
	t.Helper()
	first := graph.Described{Purl: repository + "@1a2b3c", Name: "repo", Version: "1.0"}
	second := graph.Described{Purl: repository + "@4d5e6f", Name: "repo", Version: "2.0"}
	longer := graph.Described{Purl: repository + "-common@1a2b3c", Name: "repo-common", Version: "1.0"}
	build, _ := r.Shipped(t, httpapitest.SeededBuild, "two-versions", graph.Snapshot{
		Root:       httpapitest.SeededRoot,
		Components: []graph.Described{first, second, longer},
		Dependencies: []graph.Dependency{
			{Parent: httpapitest.SeededRoot, Child: first}, {Parent: httpapitest.SeededRoot, Child: second},
			{Parent: httpapitest.SeededRoot, Child: longer},
		},
	})
	var reported []finding.Reported
	for issue, at := range map[string]graph.Described{
		"CVE-2026-0001": first, "CVE-2026-0002": second, "CVE-2026-0003": longer,
	} {
		reported = append(reported, finding.Reported{
			Issue: finding.Named{Identifier: issue, Severity: "high"}, Component: at, FixState: finding.NoFix,
		})
	}
	r.Ran(t, build, reported)
	if _, err := r.DB.DB.NewUpdate().Table("finding").
		Set(`"visibility" = ?`, "private").
		Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`,
			"CVE-2026-0002").
		Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestThePackageFilterCountsOnlyWhatTheReaderMaySee(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		shippedAtTwoVersions(t, r)
		query := "purl=" + repository
		within := map[string]string{
			"one product":        "/v1/products/mine/findings?branch_or_tag=master&variant=broadcom&" + query,
			"one product's file": "/v1/products/mine/findings.csv?branch_or_tag=master&variant=broadcom&" + query,
		}
		across := map[string]string{
			"every product":        "/v1/findings?" + query,
			"every product's file": "/v1/findings.csv?" + query,
		}
		for _, c := range []struct {
			who        string
			code, rows int
			acrossRows int
		}{
			// Both versions of the package; never the longer name.
			{"private", http.StatusOK, 2, 2},
			{"reader", http.StatusOK, 1, 1},
			// The undisclosed version alone.
			{"embargo-reader", http.StatusOK, 1, 1},
			{"triager", http.StatusOK, 1, 1},
			// Reading another product is no reading of this one.
			{"outsider", http.StatusNotFound, -1, 0},
			{"", http.StatusUnauthorized, -1, -1},
		} {
			for name, path := range within {
				if code, rows := listedUnder(t, r, c.who, path); code != c.code || rows != c.rows {
					t.Errorf("%s as %q answered %d with %d, want %d with %d", name, c.who, code, rows, c.code, c.rows)
				}
			}
			code := c.code
			if c.who == "outsider" {
				code = http.StatusOK
			}
			for name, path := range across {
				if got, rows := listedUnder(t, r, c.who, path); got != code || rows != c.acrossRows {
					t.Errorf("%s as %q answered %d with %d, want %d with %d", name, c.who, got, rows, code, c.acrossRows)
				}
			}
		}
	})
}

func TestAPackageFilterThatNamesNoPackageIsRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, path := range []string{
			"/v1/products/mine/findings?purl=sonic-repo",
			"/v1/findings?purl=pkg:github",
			"/v1/findings.csv?purl=github/sonic-net/sonic-repo",
		} {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, path, "")
			if got.Code != http.StatusUnprocessableEntity || !strings.Contains(got.Body.String(), "package identifier") {
				t.Errorf("%s answered %d, want 422 naming a package identifier: %s", path, got.Code, got.Body.String())
			}
		}
	})
}
