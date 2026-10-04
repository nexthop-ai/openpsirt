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
		{"the go line", "module m\n\ngo 1.27.1\n", "v1.27.1"},
		{"a toolchain line, over the go line", "module m\n\ngo 1.27.1\n\ntoolchain go1.27.3\n", "v1.27.3"},
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

func TestAnAffectedRangeIncludesItsStartAndExcludesItsFix(t *testing.T) {
	spans := []span{{introduced: "v1.2.0", fixed: "v1.4.0"}, {introduced: "v2.0.0"}}
	for version, want := range map[string]bool{
		"v1.1.9": false, // before it opened
		"v1.2.0": true,  // where it opened
		"v1.3.9": true,
		"v1.4.0": false, // fixed
		"v2.5.0": true,  // a span with no fix
		"":       false, // not a version
	} {
		if got := affects(spans, version); got != want {
			t.Errorf("%q: affected %v, want %v", version, got, want)
		}
	}
	if !affects([]span{{introduced: "v0", fixed: "v1.0.0"}}, "v0.0.1") {
		t.Error("a span introduced at zero did not cover the first version")
	}
}

// A module at v1.0 carries F, fixed in v1.1, and U, fixed nowhere. The bump
// to v1.1 is the change a security update makes.
const partialFix = `{"config":{"scanner_name":"govulncheck"}}
{"osv":{"id":"GO-U","summary":"unfixed","affected":[{"package":{"name":"example.com/m"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}}
{"osv":{"id":"GO-N","summary":"new in v1.1","affected":[{"package":{"name":"example.com/m"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.1.0"},{"fixed":"1.2.0"}]}]}]}}
{"osv":{"id":"GO-S","summary":"a module the base did not have","affected":[{"package":{"name":"example.com/added"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}}
{"finding":{"osv":"GO-U","trace":[{"module":"example.com/m","version":"v1.1.0","function":"F"}]}}
{"finding":{"osv":"GO-N","trace":[{"module":"example.com/m","version":"v1.1.0","function":"F"}]}}
{"finding":{"osv":"GO-S","trace":[{"module":"example.com/added","version":"v1.0.0","function":"F"}]}}
`

func TestABumpThatFixesOneAdvisoryIntroducesNoneItLeft(t *testing.T) {
	scan, err := goFindings(strings.NewReader(partialFix))
	if err != nil {
		t.Fatal(err)
	}
	base := map[string]string{"example.com/m": "v1.0.0"}
	introduced, present := split(scan.found, goAffectedBefore(scan, base))
	if got := ids(present); got != "GO-U@example.com/m" {
		t.Errorf("present %q; the base was affected by GO-U at v1.0.0", got)
	}
	if got := ids(introduced); got != "GO-N@example.com/m GO-S@example.com/added" {
		t.Errorf("introduced %q; v1.0.0 is outside GO-N, and the base had no example.com/added", got)
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
	scan, err := goFindings(strings.NewReader(govulncheckOut))
	if err != nil {
		t.Fatal(err)
	}
	found := scan.found
	if len(found) != 1 || found[0].ID != "GO-2026-1" || found[0].Name != "golang.org/x/net" ||
		found[0].Title != "reached" {
		t.Errorf("found %+v, want GO-2026-1 once, in golang.org/x/net", found)
	}
}

func TestGovulncheckOutputWithoutAConfigurationIsRefused(t *testing.T) {
	if _, err := goFindings(strings.NewReader(`{"osv":{"id":"GO-2026-1"}}`)); err == nil {
		t.Error("a stream with no configuration message read as a clean scan")
	}
}

func TestAGovulncheckRunThatFailsAfterItsConfigurationFails(t *testing.T) {
	// The configuration is printed before packages load, so a load error
	// leaves a stream that reads as a clean scan.
	failing := []string{"sh", "-c", `echo '{"config":{"scanner_name":"govulncheck"}}'; echo 'no such package' >&2; exit 1`}
	if _, err := scan("go", ".", failing); err == nil || !strings.Contains(err.Error(), "no such package") {
		t.Errorf("a failed govulncheck run passed, or lost what it said: %v", err)
	}
	// npm exits non-zero whenever it finds anything.
	if _, err := scan("npm", ".", []string{"sh", "-c", `echo '{}'; exit 1`}); err != nil {
		t.Errorf("an npm report with findings was refused: %v", err)
	}
	if _, err := scan("npm", ".", []string{"sh", "-c", `echo 'offline' >&2; exit 1`}); err == nil {
		t.Error("an npm run that printed nothing passed")
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
	locked := map[string]string{"node_modules/braces": "3.0.3", "node_modules/x/node_modules/braces": "3.0.2"}
	found, err := npmFindings([]byte(npmOut), locked)
	if err != nil {
		t.Fatal(err)
	}
	introduced, _ := split(found, npmAffectedBefore(nil))
	if got := ids(introduced); got != "GHSA-vfj7-8cjw-p6xm@node_modules/braces GHSA-vfj7-8cjw-p6xm@node_modules/x/node_modules/braces" {
		t.Errorf("found %q", got)
	}
	for _, a := range found {
		if a.Version != locked[a.Where] || a.Severity != "high" || a.Name != "braces" {
			t.Errorf("%+v does not carry the package, the locked version and the severity", a)
		}
	}
}

func TestAnNpmAdvisoryTheBaseCarriedIsPresentWhereverItMoved(t *testing.T) {
	before := []advisory{{ID: "GHSA-1", Name: "braces", Where: "node_modules/braces", Version: "3.0.2"}}
	found := []advisory{
		{ID: "GHSA-1", Name: "braces", Where: "node_modules/x/node_modules/braces", Version: "3.0.3"},
		{ID: "GHSA-2", Name: "braces", Where: "node_modules/braces", Version: "3.0.3"},
		{ID: "GHSA-1", Name: "other", Where: "node_modules/other", Version: "1.0.0"},
	}
	introduced, present := split(found, npmAffectedBefore(before))
	if got := ids(present); got != "GHSA-1@node_modules/x/node_modules/braces" {
		t.Errorf("present %q", got)
	}
	if got := ids(introduced); got != "GHSA-1@node_modules/other GHSA-2@node_modules/braces" {
		t.Errorf("introduced %q", got)
	}
}

func TestAnNpmReportWithoutAVersionIsRefused(t *testing.T) {
	if _, err := npmFindings([]byte(`{"vulnerabilities":{}}`), nil); err == nil {
		t.Error("a report with no version read as a clean audit")
	}
	_, err := npmFindings([]byte(`{"message":"request to https://registry.npmjs.org failed, reason: ECONNREFUSED"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "ECONNREFUSED") {
		t.Errorf("npm's own reason for making no report was lost: %v", err)
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
