// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// fixedOn618 is fixed on 6.18.y at 6.18.27 and on 6.19.y at 6.19.14.
var fixedOn618 = cverecord.Record{ID: "CVE-2026-31589", Affected: []cverecord.Entry{
	{Vendor: "Linux", Product: "Linux", DefaultStatus: "affected", Versions: []cverecord.Line{
		{Version: "6.14", Status: "affected"},
		{Version: "6.18.27", LessThanOrEqual: "6.18.*", Status: "unaffected", VersionType: "semver"},
		{Version: "6.19.14", LessThanOrEqual: "6.19.*", Status: "unaffected", VersionType: "semver"},
	}},
}}

func snapshotHolding(t *testing.T, records ...cverecord.Record) *cverecord.Snapshot {
	t.Helper()
	var written bytes.Buffer
	if err := cverecord.Write(&written, time.Now(), "", records); err != nil {
		t.Fatal(err)
	}
	snapshot, err := cverecord.Read(&written)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func upstreamKernel(version string) graph.Described {
	return graph.Described{
		Name: "linux", Version: version, Purl: "pkg:generic/linux@" + version,
		CPE: "cpe:2.3:o:linux:linux_kernel:" + version + ":*:*:*:*:*:*:*",
	}
}

// reportOf is the scanner's account of a match, which carries the artifact's
// name, version and identifier and nothing a record is tied by.
func reportOf(component graph.Described) finding.Reported {
	return finding.Reported{
		Issue:     finding.Named{Identifier: "CVE-2026-31589"},
		Component: graph.Described{Name: component.Name, Version: component.Version, Purl: component.Purl},
		FixState:  finding.FixedUpstream, FixedIn: "6.19.14, 7.0.1",
		FixedAt: func() *time.Time { d := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC); return &d }(),
	}
}

func TestARecordExcludingTheInventorysVersionMarksTheReport(t *testing.T) {
	// The inventory's component is what is tied, because it carries the CPE
	// the scanner's artifact does not.
	inventory := []graph.Described{upstreamKernel("6.18.55")}
	reported := []finding.Reported{reportOf(inventory[0])}
	if err := narrow(snapshotHolding(t, fixedOn618), inventory, reported); err != nil {
		t.Fatal(err)
	}
	if reported[0].Unaffected == "" {
		t.Error("a report the record excludes was not marked")
	}
}

func TestAFixOnTheBranchReplacesTheScannersOnAnUpstreamRelease(t *testing.T) {
	inventory := []graph.Described{upstreamKernel("6.18.20")}
	reported := []finding.Reported{reportOf(inventory[0])}
	if err := narrow(snapshotHolding(t, fixedOn618), inventory, reported); err != nil {
		t.Fatal(err)
	}
	r := reported[0]
	if r.Unaffected != "" {
		t.Error("an affected release was marked unaffected")
	}
	if r.FixedIn != "6.18.27" || r.FixedAt != nil {
		t.Errorf("fixed in %q at %v, want the branch's own fix and no date", r.FixedIn, r.FixedAt)
	}
}

func TestADistributionsPackageKeepsItsFeedsFix(t *testing.T) {
	// The feed's fix is in the distribution's numbering and already on its
	// branch; the record's is neither.
	debian := graph.Described{
		Name: "linux-image-amd64", Version: "6.18.20-1", UpstreamName: "linux",
		Purl: "pkg:deb/debian/linux-image-amd64@6.18.20-1",
	}
	reported := []finding.Reported{reportOf(debian)}
	reported[0].FixedIn = "6.18.30-1"
	if err := narrow(snapshotHolding(t, fixedOn618), []graph.Described{debian}, reported); err != nil {
		t.Fatal(err)
	}
	if reported[0].FixedIn != "6.18.30-1" {
		t.Errorf("a distribution's package was told to move to %q", reported[0].FixedIn)
	}
}

func TestNoSnapshotLeavesEveryReportAsTheScannerMadeIt(t *testing.T) {
	inventory := []graph.Described{upstreamKernel("6.18.55")}
	reported := []finding.Reported{reportOf(inventory[0])}
	if err := narrow(nil, inventory, reported); err != nil {
		t.Fatal(err)
	}
	if reported[0].Unaffected != "" || reported[0].FixedIn != "6.19.14, 7.0.1" {
		t.Errorf("with no snapshot, the report became %+v", reported[0])
	}
}
