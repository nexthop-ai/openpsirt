// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"os"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/scanner"
)

// perfMatch is one match of linux-perf, a binary Debian builds from the linux
// source package, reached by the details given.
func perfMatch(details string) string {
	return `{
	  "matches": [{
	    "vulnerability": {"id": "CVE-2024-26600", "severity": "High"},
	    "artifact": {"name": "linux-perf", "version": "6.12.117-1",
	      "purl": "pkg:deb/debian/linux-perf@6.12.117-1?arch=amd64&distro=debian-13&upstream=linux"},
	    "matchDetails": [` + details + `]
	  }],
	  "descriptor": {"name": "grype", "version": "0.121.3"}
	}`
}

// throughLinux is a detail matching through the linux source package, as the
// scanner writes one.
const throughLinux = `{"type": "exact-indirect-match", "matcher": "dpkg-matcher",
	"searchedBy": {"distro": {"type": "debian", "version": "13"},
	  "package": {"name": "Linux", "version": "6.12.117-1"}, "namespace": "debian:distro:debian:13"},
	"found": {"vulnerabilityID": "CVE-2024-26600", "versionConstraint": "< 6.12.118-1 (deb)"}}`

func throughOf(t *testing.T, output string) string {
	t.Helper()
	result, err := scanner.ParseGrype(strings.NewReader(output), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return result.Reported[0].MatchedThrough
}

func TestAMatchThroughTheSourcePackageNamesTheSource(t *testing.T) {
	if got := throughOf(t, perfMatch(throughLinux)); got != "linux" {
		t.Errorf("a match through the source reads as through %q, want linux", got)
	}
	if got := throughOf(t, perfMatch(throughLinux+","+throughLinux)); got != "linux" {
		t.Errorf("two details through one source read as through %q, want linux", got)
	}
}

func TestAMatchOnTheBinaryItselfIsThroughNoSource(t *testing.T) {
	for name, details := range map[string]string{
		"its own name": throughLinux + `, {"type": "exact-direct-match",
			"searchedBy": {"package": {"name": "linux-perf"}}}`,
		"a CPE":            throughLinux + `, {"type": "cpe-match", "searchedBy": {"cpes": ["cpe:2.3:a:linux:perf"]}}`,
		"two sources":      throughLinux + `, {"type": "exact-indirect-match", "searchedBy": {"package": {"name": "linux-signed"}}}`,
		"no source named":  `{"type": "exact-indirect-match", "searchedBy": {}}`,
		"the binary named": `{"type": "exact-indirect-match", "searchedBy": {"package": {"name": "LINUX-PERF"}}}`,
		"no detail":        ``,
	} {
		if got := throughOf(t, perfMatch(details)); got != "" {
			t.Errorf("a match on %s reads as through %q, want through none", name, got)
		}
	}
}

func TestARealSourceMatchNamesItsSource(t *testing.T) {
	// The scanner's own output for a SONiC kernel image, which Debian files
	// under the linux source package.
	raw, err := os.ReadFile("testdata/grype-known-exploited.json")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanner.ParseGrype(strings.NewReader(string(raw)), scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range result.Reported {
		if strings.HasPrefix(r.Component.Name, "linux-image-") {
			seen++
			if r.MatchedThrough != "linux" {
				t.Errorf("%s in %s reads as through %q, want linux", r.Issue.Identifier, r.Component.Name, r.MatchedThrough)
			}
		}
	}
	if seen == 0 {
		t.Fatal("the report matched no kernel image, so this checked nothing")
	}
}
