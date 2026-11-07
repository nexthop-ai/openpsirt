// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// repository is a source repository the build ships at two commits.
const repository = "pkg:github/sonic-net/sonic-repo"

// shippedAtTwoCommits is one repository at two commits, each pulling in a
// library of its own and both pulling in a third, with an issue at each
// library; the one under both is undisclosed.
func shippedAtTwoCommits(t *testing.T, r *httpapitest.Reach) {
	t.Helper()
	first := graph.Described{Purl: repository + "@1a2b3c", Name: "repo", Version: "1.0"}
	second := graph.Described{Purl: repository + "@4d5e6f", Name: "repo", Version: "2.0"}
	one := graph.Described{Purl: "pkg:deb/debian/libone@1.0", Name: "libone", Version: "1.0"}
	two := graph.Described{Purl: "pkg:deb/debian/libtwo@1.0", Name: "libtwo", Version: "1.0"}
	both := graph.Described{Purl: "pkg:deb/debian/libboth@1.0", Name: "libboth", Version: "1.0"}
	other := graph.Described{Purl: "pkg:deb/debian/other@1.0", Name: "other", Version: "1.0"}
	build, _ := r.Shipped(t, httpapitest.SeededBuild, "two-commits", graph.Snapshot{
		Root:       httpapitest.SeededRoot,
		Components: []graph.Described{first, second, one, two, both, other},
		Dependencies: []graph.Dependency{
			{Parent: httpapitest.SeededRoot, Child: first}, {Parent: httpapitest.SeededRoot, Child: second},
			{Parent: httpapitest.SeededRoot, Child: other},
			{Parent: first, Child: one}, {Parent: second, Child: two},
			{Parent: first, Child: both}, {Parent: second, Child: both},
		},
	})
	var reported []finding.Reported
	for issue, at := range map[string]graph.Described{
		"CVE-2026-0001": one, "CVE-2026-0002": two, "CVE-2026-0003": both, "CVE-2026-0004": other,
	} {
		reported = append(reported, finding.Reported{
			Issue: finding.Named{Identifier: issue, Severity: "high"}, Component: at, FixState: finding.NoFix,
		})
	}
	r.Ran(t, build, reported)
	if _, err := r.DB.DB.NewUpdate().Table("finding").
		Set(`"visibility" = ?`, "private").
		Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`,
			"CVE-2026-0003").
		Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// countedBeneath is what one route says is open beneath the repository, read
// as somebody, or -1 where it is refused.
func countedBeneath(t *testing.T, r *httpapitest.Reach, who, route string) (int, int) {
	t.Helper()
	switch {
	case strings.HasSuffix(strings.SplitN(route, "?", 2)[0], ".csv"):
		return listedUnder(t, r, who, route)
	case strings.HasPrefix(route, "/v1/products/"):
		return listedUnder(t, r, who, route)
	}
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, route, "")
	if got.Code != http.StatusOK {
		return got.Code, -1
	}
	var body struct {
		Items []struct {
			Open int `json:"open"`
		} `json:"items"`
		Points []struct {
			Left int `json:"left"`
		} `json:"points"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	switch {
	case len(body.Points) > 0:
		return got.Code, body.Points[len(body.Points)-1].Left
	case len(body.Items) > 0:
		return got.Code, body.Items[len(body.Items)-1].Open
	}
	return got.Code, 0
}

// leftInBurndownFile is what a burndown's file says is left on its last day.
func leftInBurndownFile(t *testing.T, r *httpapitest.Reach, who, route string) (int, int) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, route, "")
	if got.Code != http.StatusOK {
		return got.Code, -1
	}
	read := csv.NewReader(strings.NewReader(got.Body.String()))
	read.FieldsPerRecord = -1
	records, err := read.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	var header, last []string
	for _, record := range records {
		switch {
		case len(record) > 0 && strings.HasPrefix(record[0], "#"):
		case header == nil:
			header = record
		case len(record) == len(header):
			last = record
		}
	}
	if last == nil {
		return got.Code, 0
	}
	left, err := strconv.Atoi(last[httpapitest.IndexOf(header, "left")])
	if err != nil {
		t.Fatal(err)
	}
	return got.Code, left
}

func TestARepositoryAtSeveralCommitsIsASubtreeOfEachCountedOnce(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		shippedAtTwoCommits(t, r)
		at := "product=mine&branch_or_tag=master&variant=broadcom&beneath_purl=" + repository
		routes := map[string]string{
			"list":            "/v1/products/mine/findings?branch_or_tag=master&variant=broadcom&beneath_purl=" + repository,
			"list's file":     "/v1/products/mine/findings.csv?branch_or_tag=master&variant=broadcom&beneath_purl=" + repository,
			"trend":           "/v1/trend?days=7&" + at,
			"burndown":        "/v1/burndown?" + at,
			"burndown's file": "/v1/burndown.csv?" + at,
		}
		for _, c := range []struct {
			who        string
			code, open int
		}{
			// Each commit's own library and the one under both, counted once;
			// never the component beside the repository.
			{"private", http.StatusOK, 3},
			{"reader", http.StatusOK, 2},
			// The undisclosed half alone.
			{"embargo-reader", http.StatusOK, 1},
			{"triager", http.StatusOK, 2},
			{"outsider", http.StatusNotFound, -1},
			{"", http.StatusUnauthorized, -1},
		} {
			for name, route := range routes {
				var code, open int
				if strings.HasPrefix(route, "/v1/burndown.csv") {
					code, open = leftInBurndownFile(t, r, c.who, route)
				} else {
					code, open = countedBeneath(t, r, c.who, route)
				}
				if code != c.code || open != c.open {
					t.Errorf("the %s as %q answered %d with %d, want %d with %d",
						name, c.who, code, open, c.code, c.open)
				}
			}
		}
	})
}

func TestStartingAtAPackageIsRefusedWhatItCannotAnswer(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		shippedAtTwoCommits(t, r)
		build := "/v1/products/mine/findings?branch_or_tag=master&variant=broadcom&"
		for query, want := range map[string]struct {
			code int
			says string
		}{
			"beneath_purl=" + repository + "&beneath=repo":   {http.StatusUnprocessableEntity, "send one"},
			"beneath_purl=pkg:github/sonic-net/":             {http.StatusUnprocessableEntity, "one package's identifier"},
			"beneath_purl=sonic-repo":                        {http.StatusUnprocessableEntity, "one package's identifier"},
			"beneath_purl=pkg:github/sonic-net/sonic-absent": {http.StatusNotFound, "holds no component"},
		} {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, build+query, "")
			if got.Code != want.code || !strings.Contains(got.Body.String(), want.says) {
				t.Errorf("%s answered %d, want %d saying %q: %s", query, got.Code, want.code, want.says, got.Body.String())
			}
		}
		// Across products there is no one build to walk.
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/burndown?beneath_purl="+repository, "")
		if got.Code != http.StatusUnprocessableEntity || !strings.Contains(got.Body.String(), "one build") {
			t.Errorf("no product answered %d, want 422 naming one build: %s", got.Code, got.Body.String())
		}
		// Authorized before the package is looked up: a package held and
		// one nothing holds are refused alike to somebody outside.
		for _, route := range []string{build, "/v1/burndown?product=mine&branch_or_tag=master&variant=broadcom&"} {
			held := httpapitest.AsPerson(t, r, "outsider", http.MethodGet, route+"beneath_purl="+repository, "")
			absent := httpapitest.AsPerson(t, r, "outsider", http.MethodGet,
				route+"beneath_purl=pkg:github/sonic-net/sonic-absent", "")
			if held.Code != absent.Code || held.Body.String() != absent.Body.String() {
				t.Errorf("%s outside the product: a held package answered %d %s and an absent one %d %s",
					route, held.Code, held.Body.String(), absent.Code, absent.Body.String())
			}
		}
	})
}

func TestAPackageHeldAsTooManyComponentsIsRefusedNamingOneStart(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// Exactly the most a walk starts at is answered.
		most := graph.Snapshot{Root: httpapitest.SeededRoot}
		for i := range graph.MostStarts {
			c := graph.Described{Purl: fmt.Sprintf("%s-most@%06x", repository, i), Name: "repo-most", Version: fmt.Sprint(i)}
			most.Components = append(most.Components, c)
			most.Dependencies = append(most.Dependencies, graph.Dependency{Parent: httpapitest.SeededRoot, Child: c})
		}
		r.Shipped(t, httpapitest.SeededBuild, "most-commits", most)
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings?branch_or_tag=master&variant=broadcom&beneath_purl="+repository+"-most", "")
		if got.Code != http.StatusOK {
			t.Errorf("%d components answered %d, want 200: %s", graph.MostStarts, got.Code, got.Body.String())
		}

		snap := graph.Snapshot{Root: httpapitest.SeededRoot}
		for i := range graph.MostStarts + 1 {
			c := graph.Described{Purl: fmt.Sprintf("%s@%06x", repository, i), Name: "repo", Version: fmt.Sprint(i)}
			snap.Components = append(snap.Components, c)
			snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: httpapitest.SeededRoot, Child: c})
		}
		r.Shipped(t, httpapitest.SeededBuild, "many-commits", snap)
		got = httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/findings?branch_or_tag=master&variant=broadcom&beneath_purl="+repository, "")
		if got.Code != http.StatusUnprocessableEntity || !strings.Contains(got.Body.String(), "beneath_version") {
			t.Errorf("%d components answered %d, want 422 naming beneath_version: %s",
				graph.MostStarts+1, got.Code, got.Body.String())
		}
	})
}
