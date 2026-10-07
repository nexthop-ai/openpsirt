// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// snapshotOf is a snapshot holding these records, read through the format a
// deployment reads.
func snapshotOf(t *testing.T, records ...cverecord.Record) *cverecord.Snapshot {
	t.Helper()
	var written bytes.Buffer
	if err := cverecord.Write(&written, time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), "", records); err != nil {
		t.Fatal(err)
	}
	snapshot, err := cverecord.Read(&written)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// The two shapes of kernel record the narrowing exists for, as the kernel's
// numbering authority writes them.
var (
	// Fixed on 6.18.y at 6.18.27; affected from 6.14 everywhere else until a
	// branch's own fix.
	fixedOnTheBranch = cverecord.Record{ID: "CVE-2026-31589", Affected: []cverecord.Entry{
		{Vendor: "Linux", Product: "Linux", DefaultStatus: "unaffected"},
		{Vendor: "Linux", Product: "Linux", DefaultStatus: "affected", Versions: []cverecord.Line{
			{Version: "6.14", Status: "affected"},
			{Version: "0", LessThan: "6.14", Status: "unaffected", VersionType: "semver"},
			{Version: "6.18.27", LessThanOrEqual: "6.18.*", Status: "unaffected", VersionType: "semver"},
			{Version: "6.19.14", LessThanOrEqual: "6.19.*", Status: "unaffected", VersionType: "semver"},
		}},
	}}
	// Introduced on 6.12.y at 6.12.56, in mainline at 6.18.
	introducedOnTheBranch = cverecord.Record{ID: "CVE-2026-43465", Affected: []cverecord.Entry{
		{Vendor: "Linux", Product: "Linux", DefaultStatus: "unaffected", Versions: []cverecord.Line{
			{Version: "6.12.56", LessThan: "6.13", Status: "affected", VersionType: "semver"},
		}},
		{Vendor: "Linux", Product: "Linux", DefaultStatus: "affected", Versions: []cverecord.Line{
			{Version: "6.18", Status: "affected"},
			{Version: "0", LessThan: "6.18", Status: "unaffected", VersionType: "semver"},
			{Version: "6.18.19", LessThanOrEqual: "6.18.*", Status: "unaffected", VersionType: "semver"},
		}},
	}}
)

// kernel is the upstream kernel at a version, as a build describing the
// tarball it built from names it.
func kernel(version string) graph.Described {
	return graph.Described{
		Name: "linux", Version: version, Purl: "pkg:generic/linux@" + version,
		CPE: `cpe:2.3:o:linux:linux_kernel:` + version + `:*:*:*:*:*:*:*`,
	}
}

// debianKernel is Debian's kernel package at an upstream version.
func debianKernel(namespace, version string) graph.Described {
	return graph.Described{
		Name: "linux-image-amd64", Version: version, UpstreamName: "linux",
		Purl: "pkg:deb/" + namespace + "/linux-image-amd64@" + version + "?arch=amd64",
	}
}

func TestAStableFixExcludesEveryLaterReleaseOnItsBranch(t *testing.T) {
	snapshot := snapshotOf(t, fixedOnTheBranch)
	for _, each := range []struct {
		version string
		narrows bool
	}{
		{"6.18.55", true},
		{"6.18.27", true},
		{"6.18.26", false},
		// The next branch has a fix of its own, further along.
		{"6.19.13", false},
		{"6.19.14", true},
		// The one release the record names as affected outright.
		{"6.14", false},
		{"6.13.9", true},
	} {
		verdict := snapshot.Decide([]string{"CVE-2026-31589"}, kernel(each.version))
		if verdict.Narrows() != each.narrows {
			t.Errorf("%s narrows %v, want %v", each.version, verdict.Narrows(), each.narrows)
		}
	}
}

func TestABugIntroducedLaterOnTheBranchExcludesEarlierReleasesOfIt(t *testing.T) {
	snapshot := snapshotOf(t, introducedOnTheBranch)
	for _, each := range []struct {
		version string
		narrows bool
	}{
		{"6.12.41-1", true},
		{"6.12.56-1", false},
		{"6.12.80-2", false},
		{"6.18.19-1", true},
		{"6.18.5-1", false},
	} {
		verdict := snapshot.Decide([]string{"CVE-2026-43465"}, debianKernel("debian", each.version))
		if verdict.Narrows() != each.narrows {
			t.Errorf("%s narrows %v, want %v", each.version, verdict.Narrows(), each.narrows)
		}
	}
}

func TestTheLinesThatExcludeAVersionAreTheOnesReturned(t *testing.T) {
	verdict := snapshotOf(t, fixedOnTheBranch).Decide([]string{"CVE-2026-31589"}, kernel("6.18.55"))
	if len(verdict.Unaffected) != 1 {
		t.Fatalf("%d lines, want the one covering 6.18.y", len(verdict.Unaffected))
	}
	line := verdict.Unaffected[0]
	if line.Entry != "Linux Linux" || line.Version != "6.18.27" || line.LessThanOrEqual != "6.18.*" {
		t.Errorf("returned %+v, want the 6.18.27 to 6.18.* line of Linux Linux", line)
	}
	if verdict.Record != "CVE-2026-31589" {
		t.Errorf("read record %q", verdict.Record)
	}
}

func TestAnAffectedLineContainingTheVersionStopsNarrowing(t *testing.T) {
	record := fixedOnTheBranch
	record.Affected = append([]cverecord.Entry{{Vendor: "Linux", Product: "Linux",
		Versions: []cverecord.Line{{Version: "6.18.50", LessThan: "6.18.60", Status: "affected"}}}},
		record.Affected...)
	if snapshotOf(t, record).Decide([]string{"CVE-2026-31589"}, kernel("6.18.55")).Narrows() {
		t.Error("a release one line states is affected was narrowed by another stating it is not")
	}
}

func TestAnAffectedLineThisCannotOrderStopsNarrowing(t *testing.T) {
	record := fixedOnTheBranch
	record.Affected = append([]cverecord.Entry{{Vendor: "Linux", Product: "Linux",
		Versions: []cverecord.Line{{Version: "all builds with CONFIG_X", Status: "affected", VersionType: "custom"}}}},
		record.Affected...)
	if snapshotOf(t, record).Decide([]string{"CVE-2026-31589"}, kernel("6.18.55")).Narrows() {
		t.Error("an affected line nothing here can order did not stop the narrowing")
	}
}

func TestADefaultStatusAloneNeverNarrows(t *testing.T) {
	record := cverecord.Record{ID: "CVE-2026-2", Affected: []cverecord.Entry{
		{Vendor: "Linux", Product: "Linux", DefaultStatus: "unaffected", Versions: []cverecord.Line{
			{Version: "6.1", LessThan: "6.2", Status: "affected", VersionType: "semver"},
		}},
	}}
	if snapshotOf(t, record).Decide([]string{"CVE-2026-2"}, kernel("6.18.55")).Narrows() {
		t.Error("a version no line covers was narrowed on the entry's default")
	}
}

func TestADistributionsLineIsNeverReadAgainstAnUpstreamRelease(t *testing.T) {
	// A distribution's build of 2.12 with the fix backported. Read as an
	// upstream version it says 2.14 is past the fix; the upstream entry says
	// 2.14 is affected.
	record := cverecord.Record{ID: "CVE-2025-61662", Affected: []cverecord.Entry{
		{Vendor: "GNU", Product: "grub2", CollectionURL: "https://git.savannah.gnu.org/git/grub.git",
			DefaultStatus: "unaffected", Versions: []cverecord.Line{
				{Version: "0", LessThanOrEqual: "2.14", Status: "affected"},
			}},
		{Vendor: "Red Hat", Product: "Red Hat Enterprise Linux 10", PackageName: "grub2",
			CPEs: []string{"cpe:/o:redhat:enterprise_linux:10.1"}, DefaultStatus: "affected",
			Versions: []cverecord.Line{
				{Version: "1:2.12-29.el10_1.2", LessThan: "*", Status: "unaffected", VersionType: "rpm"},
			}},
		{Vendor: "Red Hat", Product: "A product writing its builds as releases",
			CPEs: []string{"cpe:/o:redhat:enterprise_linux:10.1"}, DefaultStatus: "affected",
			Versions: []cverecord.Line{
				{Version: "2.12", LessThanOrEqual: "2.*", Status: "unaffected", VersionType: "semver"},
			}},
	}}
	grub := graph.Described{
		Name: "grub", Version: "2.14", Purl: "pkg:generic/grub@2.14",
		CPE: "cpe:2.3:a:gnu:grub2:2.14:*:*:*:*:*:*:*",
	}
	if snapshotOf(t, record).Decide([]string{"CVE-2025-61662"}, grub).Narrows() {
		t.Error("a distribution's statement about its own build narrowed an upstream release")
	}
}

func TestAKernelWhoseVersionIsNotTheStableReleaseItCarriesIsNotTied(t *testing.T) {
	// Ubuntu's kernel keeps one base version while taking in stable releases,
	// so its version says nothing about which it carries.
	for _, namespace := range []string{"ubuntu", "raspbian"} {
		verdict := snapshotOf(t, introducedOnTheBranch).Decide([]string{"CVE-2026-43465"},
			debianKernel(namespace, "6.12.41-1"))
		if verdict.Narrows() {
			t.Errorf("a %s kernel was narrowed against upstream's release numbers", namespace)
		}
	}
}

func TestAComponentNoEntryDescribesIsNotNarrowed(t *testing.T) {
	other := graph.Described{
		Name: "linux-firmware", Version: "6.18.55", Purl: "pkg:generic/linux-firmware@6.18.55",
		CPE: "cpe:2.3:a:linux:linux-firmware:6.18.55:*:*:*:*:*:*:*",
	}
	if snapshotOf(t, fixedOnTheBranch).Decide([]string{"CVE-2026-31589"}, other).Narrows() {
		t.Error("a component the record does not describe was narrowed")
	}
}

func TestAnEntryIsTiedByItsCPEOrItsPackageIdentifier(t *testing.T) {
	record := cverecord.Record{ID: "CVE-2026-3", Affected: []cverecord.Entry{
		{Vendor: "zlib", Product: "zlib", CPEs: []string{"cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"},
			Versions: []cverecord.Line{
				{Version: "1.3.1", LessThanOrEqual: "1.3.*", Status: "unaffected", VersionType: "semver"},
			}},
		{Vendor: "madler", Product: "zlib-ng", PackageURL: "pkg:github/madler/zlib-ng",
			Versions: []cverecord.Line{
				{Version: "2.2.0", LessThanOrEqual: "2.2.*", Status: "unaffected", VersionType: "semver"},
			}},
	}}
	snapshot := snapshotOf(t, record)
	byCPE := graph.Described{Name: "zlib", Version: "1.3.2", Purl: "pkg:generic/zlib@1.3.2",
		CPE: `cpe:2.3:a:zlib:zlib:1.3.2:*:*:*:*:*:*:*`}
	if !snapshot.Decide([]string{"CVE-2026-3"}, byCPE).Narrows() {
		t.Error("an entry naming the component's CPE did not narrow it")
	}
	byPurl := graph.Described{Name: "zlib-ng", Version: "2.2.4", Purl: "pkg:github/madler/zlib-ng@2.2.4"}
	if !snapshot.Decide([]string{"CVE-2026-3"}, byPurl).Narrows() {
		t.Error("an entry naming the component's package identifier did not narrow it")
	}
	// A distribution's package carrying the same CPE is the distribution's
	// build, whose own CPE ties it to nothing upstream.
	packaged := graph.Described{Name: "zlib1g", Version: "1:1.3.2-1", Purl: "pkg:deb/debian/zlib1g@1:1.3.2-1",
		CPE: `cpe:2.3:a:zlib:zlib:1\:1.3.2-1:*:*:*:*:*:*:*`}
	if snapshot.Decide([]string{"CVE-2026-3"}, packaged).Narrows() {
		t.Error("a distribution's package was tied by its own CPE")
	}
}

func TestAVersionThatIsNotAReleaseNumberIsNotNarrowed(t *testing.T) {
	for _, version := range []string{"6.18.55-onie", "6.18.55-rc1", "master", ""} {
		component := kernel(version)
		if snapshotOf(t, fixedOnTheBranch).Decide([]string{"CVE-2026-31589"}, component).Narrows() {
			t.Errorf("version %q was narrowed", version)
		}
	}
}

func TestEachBoundCoversWhatTheRecordFormatSays(t *testing.T) {
	record := cverecord.Record{ID: "CVE-2026-4", Affected: []cverecord.Entry{
		{Vendor: "Linux", Product: "Linux", Versions: []cverecord.Line{
			// Inclusive with no wildcard: 5.10.20 itself is covered.
			{Version: "5.10.1", LessThanOrEqual: "5.10.20", Status: "unaffected", VersionType: "semver"},
			// Exclusive: 5.15 is not covered, 5.14.99 is.
			{Version: "5.11", LessThan: "5.15", Status: "unaffected", VersionType: "semver"},
			// Everything from 7.1 on.
			{Version: "7.1", LessThanOrEqual: "*", Status: "unaffected", VersionType: "semver"},
		}},
	}}
	snapshot := snapshotOf(t, record)
	for _, each := range []struct {
		version string
		narrows bool
	}{
		{"5.10.20", true}, {"5.10.21", false},
		{"5.14.99", true}, {"5.15", false},
		{"7.1", true}, {"9.0.3", true}, {"7.0.9", false},
	} {
		if got := snapshot.Decide([]string{"CVE-2026-4"}, kernel(each.version)).Narrows(); got != each.narrows {
			t.Errorf("%s narrows %v, want %v", each.version, got, each.narrows)
		}
	}
}

func TestTheRecordIsFoundUnderAnAlias(t *testing.T) {
	verdict := snapshotOf(t, fixedOnTheBranch).Decide([]string{"GHSA-xxxx-xxxx-xxxx", "cve-2026-31589"}, kernel("6.18.55"))
	if !verdict.Narrows() {
		t.Error("the record held under the issue's alias was not read")
	}
}

func TestABranchFixIsTheFirstUnaffectedReleaseOnTheComponentsBranch(t *testing.T) {
	snapshot := snapshotOf(t, fixedOnTheBranch)
	for _, each := range []struct{ version, fix string }{
		{"6.18.20", "6.18.27"},
		{"6.19.1", "6.19.14"},
		// Past the branch's fix, which narrows instead.
		{"6.18.55", ""},
		// A branch the record names no fix on.
		{"6.15.3", ""},
	} {
		verdict := snapshot.Decide([]string{"CVE-2026-31589"}, kernel(each.version))
		if verdict.BranchFix != each.fix {
			t.Errorf("%s: branch fix %q, want %q", each.version, verdict.BranchFix, each.fix)
		}
	}
}

func TestNoSnapshotDecidesNothing(t *testing.T) {
	var none *cverecord.Snapshot
	if none.Decide([]string{"CVE-2026-31589"}, kernel("6.18.55")).Narrows() {
		t.Error("an absent snapshot narrowed a match")
	}
	if none.Version() != "" {
		t.Errorf("an absent snapshot has version %q", none.Version())
	}
}
