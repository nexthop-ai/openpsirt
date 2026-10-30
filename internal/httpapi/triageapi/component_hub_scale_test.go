// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the component hub's reads cost on one build of 1,000, 4,000 and 16,000
// components: the queue narrowed to a source package and beneath the build's
// root, a component's counts, the tree's code findings, and the chooser. A
// kernel source of ten binaries carries most of the dependency findings, as a
// real switch image's does, and the code findings are spread over a tenth of
// the components by repository, with a share in no repository the build
// holds, so on the build itself.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it; one engine at a time is OPENPSIRT_TEST_ENGINES.
package triageapi_test

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// hubRepositories is how many components are built from a repository of their
// own, at most, so one run states each.
const hubRepositories = 400

// hubKernelBinaries is the binary packages built from the one kernel source.
const hubKernelBinaries = 10

// hubSeeded ships a build of n components under one root: a kernel source of
// ten binaries carrying n/2 issues each, and generic packages, the first of
// which are built from a repository of their own. Then one analyzer run
// reports codeFindings results, spread over those repositories, the kernel's
// and one the build does not hold.
func hubSeeded(t *testing.T, r *httpapitest.Reach, n, codeFindings int) {
	t.Helper()
	root := graph.Described{Purl: "pkg:generic/sonic-image@1.0", Name: "sonic-image", Version: "1.0"}
	var components []graph.Described
	var edges []graph.Dependency
	var reported []finding.Reported
	for i := range hubKernelBinaries {
		k := graph.Described{
			Purl: fmt.Sprintf("pkg:deb/debian/linux-image-%d@6.1.0-1", i), Name: fmt.Sprintf("linux-image-%d", i),
			Version: "6.1.0-1", UpstreamName: "linux", UpstreamVersion: "6.1.0",
			Repository: "https://github.com/acme/linux",
		}
		components = append(components, k)
		edges = append(edges, graph.Dependency{Parent: root, Child: k})
		for v := range n / 2 {
			reported = append(reported, finding.Reported{
				Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%d", 100000+v), Severity: "medium"},
				Component: k, FixState: finding.NoFix,
			})
		}
	}
	for i := len(components); i < n; i++ {
		c := graph.Described{
			Purl: fmt.Sprintf("pkg:generic/pkg-%d@1.0", i), Name: fmt.Sprintf("pkg-%d", i), Version: "1.0",
		}
		if i < hubRepositories {
			c.Repository = fmt.Sprintf("https://github.com/acme/repo-%d", i)
		}
		components = append(components, c)
		edges = append(edges, graph.Dependency{Parent: root, Child: c})
		if i%50 == 0 {
			reported = append(reported, finding.Reported{
				Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%d", i), Severity: "low"},
				Component: c, FixState: finding.NoFix,
			})
		}
	}
	_, scan := r.ScanAt(t, httpapitest.SeededBuild, fmt.Sprintf("hub-%d", n), graph.Snapshot{
		Root: root, Components: components, Dependencies: edges,
	}, reported)
	if err := ingest.NewStore(r.DB.DB).Made(t.Context(), scan, n+1, n+1, root.Name); err != nil {
		t.Fatal(err)
	}

	// The repositories the run states: the kernel's, each package's own up
	// to the bound, and one nothing in the build is built from.
	repositories := []string{"https://github.com/acme/linux", "https://github.com/acme/elsewhere"}
	for i := hubKernelBinaries; i < min(n, hubRepositories); i++ {
		repositories = append(repositories, fmt.Sprintf("https://github.com/acme/repo-%d", i))
	}
	bases := make([]string, 0, len(repositories))
	modules := make([]string, 0, len(repositories))
	for i, repository := range repositories {
		bases = append(bases, fmt.Sprintf(`"M%d":{"uri":"file:///build/m%d/"}`, i, i))
		modules = append(modules, fmt.Sprintf(`{"repositoryUri":"%s","revisionId":"%s","mappedTo":{"uriBaseId":"M%d"}}`,
			repository, httpapitest.CodeFindingCommit, i))
	}
	results := make([]string, 0, codeFindings)
	for i := range codeFindings {
		results = append(results, fmt.Sprintf(`{"ruleId":"r%d","message":{"text":"code finding %d"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/f%05d.c","uriBaseId":"M%d"},`+
			`"region":{"startLine":%d}}}]}`, i%8, i, i/20, i%len(repositories), 10+5*(i%20)))
	}
	rules := make([]string, 0, 8)
	for i := range 8 {
		rules = append(rules, fmt.Sprintf(`{"id":"r%d"}`, i))
	}
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clang","rules":[` + strings.Join(rules, ",") + `]}},` +
		`"originalUriBaseIds":{` + strings.Join(bases, ",") + `},` +
		`"versionControlProvenance":[` + strings.Join(modules, ",") + `],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[` + strings.Join(results, ",") + `]}]}`
	httpapitest.ApplyRunIn(t, r, "clang/measured", time.Now().UTC().Add(-time.Hour), doc)
}

func TestMeasureTheComponentHub(t *testing.T) {
	const build = "/v1/products/mine/branches-and-tags/master/variants/broadcom"
	for _, n := range []int{1000, 4000, 16000} {
		t.Run(fmt.Sprintf("%d components", n), func(t *testing.T) {
			httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
				began := time.Now()
				hubSeeded(t, r, n, 4000)
				t.Logf("%d components: seeded in %s", n, time.Since(began).Round(time.Second))
				paths := []string{
					// The queue of the build with no narrowing, which beneath
					// the root is.
					"/v1/products/mine/code-findings?branch_or_tag=master&variant=broadcom",
					"/v1/products/mine/code-findings?component=linux",
					"/v1/products/mine/code-findings?component=pkg-17&state=open",
					"/v1/products/mine/code-findings?component=sonic-image",
					"/v1/products/mine/code-findings?beneath=sonic-image&branch_or_tag=master&variant=broadcom",
					"/v1/products/mine/code-findings?beneath=pkg-17&branch_or_tag=master&variant=broadcom",
					"/v1/products/mine/components/linux/code-finding-counts",
					"/v1/products/mine/components/sonic-image/code-finding-counts",
					build + "/components?code_findings=true",
					build + "/components/pkg-17/around?code_findings=true",
					build + "/components/sonic-image/code-finding-trend",
					"/v1/components?q=linux",
					"/v1/components?q=pkg-1",
				}
				timed(t, r, fmt.Sprintf("%d components", n), paths)
			})
		})
	}
}

// hubHistory is how many times the history measurement copies a build's live
// nodes as closed ones: a node is never deleted, so a build rescanned that
// often at moving versions holds that many of each.
const hubHistory = 100

// TestMeasureTheComponentHubOverAHistory times the reads that ask for every
// root a build has had, or every version of a name, on a build of 4,000
// components holding a hundred closed copies of each node.
func TestMeasureTheComponentHubOverAHistory(t *testing.T) {
	const n = 4000
	const build = "/v1/products/mine/branches-and-tags/master/variants/broadcom"
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		began := time.Now()
		hubSeeded(t, r, n, 4000)
		for range hubHistory {
			if _, err := r.DB.DB.NewRaw(`INSERT INTO "graph_node" ("build_id", "component_id", "is_root",
					"opened_scan_id", "closed_scan_id", "purl", "cpe", "upstream_name", "upstream_version", "repository")
				SELECT "build_id", "component_id", "is_root", "opened_scan_id", "opened_scan_id", "purl", "cpe",
					"upstream_name", "upstream_version", "repository"
				FROM "graph_node" WHERE "build_id" = ? AND "closed_scan_id" IS NULL`, r.BuildOf(t, httpapitest.SeededBuild)).
				Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("%d components, %d closed copies of each node: seeded in %s", n, hubHistory, time.Since(began).Round(time.Second))
		if err := database.RefreshStatistics(t.Context(), r.DB); err != nil {
			t.Fatal(err)
		}
		// The read of every root the build has had, on its own: the median of
		// three after one to warm.
		var took []time.Duration
		for i := range 4 {
			var rows []struct {
				BuildID     int64 `bun:"build_id"`
				ComponentID int64 `bun:"component_id"`
				Live        int   `bun:"live"`
			}
			began := time.Now()
			if err := r.DB.DB.NewRaw(`SELECT "n"."build_id", "n"."component_id",
					MAX(CASE WHEN "n"."closed_scan_id" IS NULL THEN 1 ELSE 0 END) AS "live"
				FROM "graph_node" AS "n" WHERE "n"."build_id" IN (?) AND "n"."is_root" = ?
				GROUP BY "n"."build_id", "n"."component_id"`,
				bun.List([]int64{r.BuildOf(t, httpapitest.SeededBuild)}), true).Scan(t.Context(), &rows); err != nil {
				t.Fatal(err)
			}
			if i > 0 {
				took = append(took, time.Since(began))
			}
		}
		slices.Sort(took)
		t.Logf("%d components over a history, every root the build has had: %s", n, took[1].Round(10*time.Microsecond))
		timed(t, r, fmt.Sprintf("%d components over a history", n), []string{
			"/v1/products/mine/code-findings?component=sonic-image",
			"/v1/products/mine/code-findings?component=pkg-17&state=open",
			"/v1/products/mine/code-findings?component=linux",
			"/v1/products/mine/components/sonic-image/code-finding-counts",
			"/v1/products/mine/components/pkg-17/code-finding-counts",
			build + "/components?code_findings=true",
			build + "/components/pkg-17/around?code_findings=true",
			build + "/components?q=pkg-1&code_findings=true",
			"/v1/products/mine/code-findings?beneath=pkg-17&branch_or_tag=master&variant=broadcom",
			build + "/components/pkg-17/code-finding-trend",
			"/v1/components?q=sonic",
			"/v1/components?q=pkg-1",
		})
	})
}

// timed logs the median of three reads of each path, once on the statistics
// the load leaves behind and once after they are refreshed, as a server's own
// refresh does. The first read warms the connection and the caches.
func timed(t *testing.T, r *httpapitest.Reach, label string, paths []string) {
	t.Helper()
	for _, stats := range []string{"as loaded", "refreshed"} {
		if stats == "refreshed" {
			if err := database.RefreshStatistics(t.Context(), r.DB); err != nil {
				t.Fatal(err)
			}
		}
		for _, path := range paths {
			var took []time.Duration
			var body string
			for i := range 4 {
				began := time.Now()
				got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodGet, path, "")
				if i > 0 {
					took = append(took, time.Since(began))
				}
				if got.Code != http.StatusOK {
					t.Fatalf("GET %s answered %d: %s", path, got.Code, got.Body.String())
				}
				body = got.Body.String()
			}
			slices.Sort(took)
			t.Logf("%s, %s, GET %s: %s, %s", label, stats, path, took[1].Round(time.Millisecond), said(body))
		}
	}
}

// said is the figures an answer carries, so a measurement reading nothing is
// seen to read nothing.
func said(body string) string {
	var out []string
	for _, key := range []string{`"total":`, `"code_findings":`, `"code_findings_beneath":`, `"open":`, `"unplaced":`, `"not_fixed":`, `"issues":`} {
		if at := strings.Index(body, key); at >= 0 {
			end := at + len(key)
			for end < len(body) && body[end] >= '0' && body[end] <= '9' {
				end++
			}
			out = append(out, body[at:end])
		}
	}
	return strings.Join(out, " ")
}
