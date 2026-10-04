// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func ids(list []advisory) string {
	var out []string
	for _, a := range list {
		out = append(out, a.ID+"@"+a.Where)
	}
	return strings.Join(out, " ")
}

func TestAnAdvisoryIsIntroducedOnlyWhereTheVersionMoved(t *testing.T) {
	found := []advisory{
		{ID: "A", Where: "unchanged"},
		{ID: "B", Where: "bumped"},
		{ID: "C", Where: "added"},
		{ID: "D", Where: "unversioned"},
	}
	now := versions{"unchanged": "1.0", "bumped": "2.0", "added": "1.0", "unversioned": ""}
	base := versions{"unchanged": "1.0", "bumped": "1.0", "unversioned": ""}
	introduced, present := split(found, now, base)
	if got := ids(introduced); got != "B@bumped C@added D@unversioned" {
		t.Errorf("introduced %q", got)
	}
	if got := ids(present); got != "A@unchanged" {
		t.Errorf("present %q", got)
	}
}

func TestOnlyAnIntroducedAdvisoryFailsAChange(t *testing.T) {
	out, passed := report("npm", "origin/main", nil,
		[]advisory{{ID: "GHSA-1", Where: "node_modules/braces", Severity: "high"}})
	if !passed {
		t.Errorf("an advisory already on the base failed the change:\n%s", out)
	}
	if !strings.Contains(out, "already on origin/main") {
		t.Errorf("an advisory already on the base was not reported:\n%s", out)
	}

	out, passed = report("npm", "origin/main",
		[]advisory{{ID: "GHSA-2", Where: "node_modules/x", Severity: "critical"}}, nil)
	if passed {
		t.Errorf("an introduced critical advisory passed:\n%s", out)
	}
}

func TestAnIntroducedNpmAdvisoryBelowHighIsReportedAndPasses(t *testing.T) {
	out, passed := report("npm", "origin/main",
		[]advisory{{ID: "GHSA-3", Where: "node_modules/x", Severity: "moderate"}}, nil)
	if !passed {
		t.Errorf("a moderate advisory failed the change:\n%s", out)
	}
	if !strings.Contains(out, "GHSA-3") {
		t.Errorf("a moderate advisory was not reported:\n%s", out)
	}
}

func TestEveryReachableGoFindingGates(t *testing.T) {
	if !gating(advisory{ID: "GO-2026-1"}) {
		t.Error("a Go finding, which carries no severity, did not gate")
	}
}

func TestTheStandardLibraryIsTheDeclaredToolchain(t *testing.T) {
	for _, c := range []struct {
		what, mod, want string
	}{
		{"the go line", "module m\n\ngo 1.27.1\n", "1.27.1"},
		{"a toolchain line, over the go line", "module m\n\ngo 1.27.1\n\ntoolchain go1.27.3\n", "1.27.3"},
	} {
		held, err := goVersions([]byte(c.mod))
		if err != nil {
			t.Fatal(err)
		}
		if held[stdlib] != c.want {
			t.Errorf("%s: stdlib is %q, want %q", c.what, held[stdlib], c.want)
		}
	}
	held, err := goVersions([]byte("module m\n\ngo 1.27.1\n\nrequire (\n\tgolang.org/x/net v0.1.0 // indirect\n)\n"))
	if err != nil {
		t.Fatal(err)
	}
	if held["golang.org/x/net"] != "v0.1.0" {
		t.Errorf("an indirect requirement read as %q", held["golang.org/x/net"])
	}
}

const govulncheckOut = `{"config":{"scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2026-1","summary":"reached"}}
{"osv":{"id":"GO-2026-2","summary":"imported, never called"}}
{"finding":{"osv":"GO-2026-1","trace":[{"module":"golang.org/x/net","version":"v0.1.0"}]}}
{"finding":{"osv":"GO-2026-1","trace":[{"module":"golang.org/x/net","version":"v0.1.0","package":"golang.org/x/net/html","function":"Parse"}]}}
{"finding":{"osv":"GO-2026-1","trace":[{"module":"golang.org/x/net","version":"v0.1.0","package":"golang.org/x/net/html","function":"ParseFragment"}]}}
{"finding":{"osv":"GO-2026-2","trace":[{"module":"stdlib","version":"v1.27.1","package":"net/mail"}]}}
`

func TestAGoFindingCountsWhereSomethingCallsIt(t *testing.T) {
	found, err := goFindings(strings.NewReader(govulncheckOut))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ID != "GO-2026-1" || found[0].Where != "golang.org/x/net" ||
		found[0].Title != "reached" {
		t.Errorf("found %+v, want GO-2026-1 once, in golang.org/x/net", found)
	}
}

func TestGovulncheckOutputWithoutAConfigurationIsRefused(t *testing.T) {
	if _, err := goFindings(strings.NewReader(`{"osv":{"id":"GO-2026-1"}}`)); err == nil {
		t.Error("a stream with no configuration message read as a clean scan")
	}
}

const npmOut = `{
  "auditReportVersion": 2,
  "vulnerabilities": {
    "braces": {
      "via": [{"name": "braces", "title": "deep nesting", "url": "https://github.com/advisories/GHSA-vfj7-8cjw-p6xm", "severity": "high"}],
      "nodes": ["node_modules/braces", "node_modules/x/node_modules/braces"]
    },
    "micromatch": {
      "via": ["braces"],
      "nodes": ["node_modules/micromatch"]
    }
  }
}`

func TestAnNpmAdvisoryIsCountedAtEachPlaceAndNotOnWhatPullsItIn(t *testing.T) {
	locked := versions{"node_modules/braces": "3.0.3", "node_modules/x/node_modules/braces": "3.0.2"}
	found, err := npmFindings([]byte(npmOut), locked)
	if err != nil {
		t.Fatal(err)
	}
	introduced, _ := split(found, locked, versions{})
	if got := ids(introduced); got != "GHSA-vfj7-8cjw-p6xm@node_modules/braces GHSA-vfj7-8cjw-p6xm@node_modules/x/node_modules/braces" {
		t.Errorf("found %q", got)
	}
	for _, a := range found {
		if a.Version != locked[a.Where] || a.Severity != "high" {
			t.Errorf("%+v does not carry the locked version and the severity", a)
		}
	}
}

func TestAnNpmReportWithoutAVersionIsRefused(t *testing.T) {
	if _, err := npmFindings([]byte(`{"vulnerabilities":{}}`), versions{}); err == nil {
		t.Error("a report with no version read as a clean audit")
	}
}

func TestTheLockfileIsReadByPlace(t *testing.T) {
	held, err := npmVersions([]byte(`{"packages":{"":{"version":"0.0.0"},"node_modules/braces":{"version":"3.0.3"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 || held["node_modules/braces"] != "3.0.3" {
		t.Errorf("read %v; the root entry is the project itself and not a package", held)
	}
}
