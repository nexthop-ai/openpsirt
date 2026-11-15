// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"sort"
	"testing"
)

// Facts about one issue are ordered by what they are about and then by where,
// so a build's document is the same bytes however its rows were read, and a
// publish pass comparing them sees no revision where nothing changed.
func TestFactsAboutOneIssueAreOrderedBySubjectThenWhere(t *testing.T) {
	facts := []Fact{
		{Issue: "CVE-2026-1", Purl: "pkg:deb/debian/zlib@1", Within: ""},
		{Issue: "CVE-2026-1", Purl: "pkg:deb/debian/libnl@3", Within: "pkg:deb/debian/sonic@2"},
		{Issue: "CVE-2026-1", Purl: "pkg:deb/debian/libnl@3", Within: "pkg:deb/debian/sonic@1"},
		{Issue: "CVE-2026-0", Purl: "pkg:deb/debian/zlib@1"},
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].before(facts[j]) })
	want := []struct{ issue, subject, within string }{
		{"CVE-2026-0", "pkg:deb/debian/zlib@1", ""},
		{"CVE-2026-1", "pkg:deb/debian/libnl@3", "pkg:deb/debian/sonic@1"},
		{"CVE-2026-1", "pkg:deb/debian/libnl@3", "pkg:deb/debian/sonic@2"},
		{"CVE-2026-1", "pkg:deb/debian/zlib@1", ""},
	}
	for i, w := range want {
		got := facts[i]
		if got.Issue != w.issue || got.Subject() != w.subject || got.Within != w.within {
			t.Errorf("fact %d is %s %s within %q, want %s %s within %q",
				i, got.Issue, got.Subject(), got.Within, w.issue, w.subject, w.within)
		}
	}
}
