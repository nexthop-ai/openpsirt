// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// The seeded build as the component hub reads it: an image whose library is
// built from a repository, a second binary of the library's source built from
// none, and a compression library under the library built from a repository
// of its own.
var (
	HubRoot = graph.Described{Purl: "pkg:generic/sonic-image@1.0", Name: "sonic-image", Version: "1.0"}
	HubLib  = graph.Described{
		Purl: "pkg:deb/debian/libmine1@2.0-1", Name: "libmine1", Version: "2.0-1",
		UpstreamName: "mine-src", UpstreamVersion: "2.0", Repository: "https://github.com/acme/mine",
	}
	HubTools = graph.Described{
		Purl: "pkg:deb/debian/mine-tools@2.0-1", Name: "mine-tools", Version: "2.0-1",
		UpstreamName: "mine-src", UpstreamVersion: "2.0",
	}
	HubZlib = graph.Described{
		Purl: "pkg:deb/debian/zlib1g@1.3", Name: "zlib1g", Version: "1.3",
		Repository: "https://github.com/acme/zlib",
	}
)

// RunInRepository is one run of tool over one repository, reporting rule at
// line of file, the rule tagged with no weakness. Its rule list holds a rule
// that never fires, so the list is the rule set.
func RunInRepository(tool, repository, file string, line int) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + tool + `","rules":[` +
		`{"id":"bad"},{"id":"unfired"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///build/"}},` +
		`"versionControlProvenance":[{"repositoryUri":"` + repository + `","revisionId":"` + CodeFindingCommit + `","mappedTo":{"uriBaseId":"SRCROOT"}}],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[{"ruleId":"bad","message":{"text":"bad here"},` +
		`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"` + file + `","uriBaseId":"SRCROOT"},` +
		`"region":{"startLine":` + strconv.Itoa(line) + `}}}]}]}]}`
}

// HubCodeFindings ships the hub's build with one open issue on the library
// and three open code findings, one per series: clang-tidy's on the library,
// cppcheck's on the compression library under it, and semgrep's in a
// repository nothing in the build is built from, so on the build itself.
func HubCodeFindings(t *testing.T, r *Reach) {
	t.Helper()
	HubCodeFindingsUnder(t, r, []graph.Dependency{
		{Parent: HubRoot, Child: HubLib}, {Parent: HubRoot, Child: HubTools},
		{Parent: HubLib, Child: HubZlib},
	})
}

// HubCodeFindingsUnder is HubCodeFindings with the build's edges given: an
// inventory stating no edge from its root leaves what it holds hanging from
// nothing.
func HubCodeFindingsUnder(t *testing.T, r *Reach, edges []graph.Dependency) {
	t.Helper()
	_, scan := r.ScanAt(t, SeededBuild, "hub", graph.Snapshot{
		Root:         HubRoot,
		Components:   []graph.Described{HubLib, HubTools, HubZlib},
		Dependencies: edges,
	}, []finding.Reported{{
		Issue: finding.Named{Identifier: "CVE-2026-4242", Severity: "high"}, Component: HubLib, FixState: finding.NoFix,
	}})
	// Marked made, as reading the inventory does, so a run has a build to
	// place its results in.
	if err := ingest.NewStore(r.DB.DB).Made(t.Context(), scan, 4, 4, HubRoot.Name); err != nil {
		t.Fatal(err)
	}
	built := time.Now().UTC().Add(-2 * time.Hour)
	ApplyRunIn(t, r, "clang-tidy/default", built, CodeFindingRun(true))
	ApplyRunIn(t, r, "cppcheck/default", built,
		RunInRepository("cppcheck", "https://github.com/acme/zlib", "inflate.cpp", 40))
	ApplyRunIn(t, r, "semgrep/default", built,
		RunInRepository("semgrep", "https://github.com/acme/elsewhere", "main.go", 7))
}

// HubRootRescanned scans the hub's build again with its root at a new
// version, so the code finding on the build itself stays on the root it
// opened on, which the build no longer holds.
func HubRootRescanned(t *testing.T, r *Reach) {
	t.Helper()
	root := HubRoot
	root.Purl, root.Version = "pkg:generic/sonic-image@1.1", "1.1"
	r.ScanAt(t, SeededBuild, "hub-rescanned", graph.Snapshot{
		Root:       root,
		Components: []graph.Described{HubLib, HubTools, HubZlib},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: HubLib}, {Parent: root, Child: HubTools},
			{Parent: HubLib, Child: HubZlib},
		},
	}, []finding.Reported{{
		Issue: finding.Named{Identifier: "CVE-2026-4242", Severity: "high"}, Component: HubLib, FixState: finding.NoFix,
	}})
}

// HubZlibRescanned scans the hub's build again with the compression library
// at a new version, so cppcheck's code finding stays on the version it opened
// on, which the build no longer holds.
func HubZlibRescanned(t *testing.T, r *Reach) {
	t.Helper()
	zlib := HubZlib
	zlib.Purl, zlib.Version = "pkg:deb/debian/zlib1g@1.4", "1.4"
	r.ScanAt(t, SeededBuild, "hub-zlib-rescanned", graph.Snapshot{
		Root:       HubRoot,
		Components: []graph.Described{HubLib, HubTools, zlib},
		Dependencies: []graph.Dependency{
			{Parent: HubRoot, Child: HubLib}, {Parent: HubRoot, Child: HubTools},
			{Parent: HubLib, Child: zlib},
		},
	}, []finding.Reported{{
		Issue: finding.Named{Identifier: "CVE-2026-4242", Severity: "high"}, Component: HubLib, FixState: finding.NoFix,
	}})
}

// HubTheirsShipsTheSource ships, in the other product, a binary of a name
// the hub's product never ships, built from the hub library's source at its
// version: one fold, reached by a name only the other product holds.
func HubTheirsShipsTheSource(t *testing.T, r *Reach) {
	t.Helper()
	root := graph.Described{Purl: "pkg:generic/theirs-image@1.0", Name: "theirs-image", Version: "1.0"}
	theirs := graph.Described{
		Purl: "pkg:deb/debian/libtheirs@2.0-1", Name: "libtheirs", Version: "2.0-1",
		UpstreamName: "mine-src", UpstreamVersion: "2.0",
	}
	r.Shipped(t, Build{"theirs", "master", "mellanox"}, "hub-theirs", graph.Snapshot{
		Root: root, Components: []graph.Described{theirs},
		Dependencies: []graph.Dependency{{Parent: root, Child: theirs}},
	})
}
