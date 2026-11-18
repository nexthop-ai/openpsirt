// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
)

// filesEntry is a kernel record's entry listing the files the issue is in, as
// the kernel's numbering authority writes one, with no version line that could
// narrow a match.
func filesEntry(files ...string) map[string]any {
	return map[string]any{
		"vendor": "Linux", "product": "Linux", "defaultStatus": "affected",
		"repo":         "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
		"programFiles": files,
		"versions": []map[string]any{
			{"version": "1da177e4", "lessThan": "4e3d5b4f", "status": "affected", "versionType": "git"},
		},
	}
}

func TestARecordListingFilesIsKeptWithNothingToNarrow(t *testing.T) {
	// CVE-2024-26600 names drivers/phy/ti/phy-omap-usb2.c. Its version lines
	// here are commit ranges alone, which narrow nothing, so it is kept for
	// its files.
	snapshot := built(t, listArchive(t, map[string][]byte{
		"CVE-2024-26600.json": published("CVE-2024-26600", "PUBLISHED", "2026-11-18T00:00:00Z",
			filesEntry("drivers/phy/ti/phy-omap-usb2.c")),
		"CVE-2026-1.json": published("CVE-2026-1", "PUBLISHED", "2026-11-18T00:00:00Z", map[string]any{
			"vendor": "x", "product": "y",
			"versions": []map[string]any{{"version": "1.0", "lessThan": "2.0", "status": "affected"}},
		}),
	}))
	if snapshot.Len() != 1 {
		t.Fatalf("kept %d records, want the one listing files", snapshot.Len())
	}
	listed := snapshot.Files([]string{"DSA-1", "cve-2024-26600"})
	if !listed.Held || !slices.Equal(listed.Files, []string{"drivers/phy/ti/phy-omap-usb2.c"}) {
		t.Errorf("read %+v, want the file the record lists, found by an alias", listed)
	}
	if listed := snapshot.Files([]string{"CVE-2026-1"}); !listed.Held || len(listed.Files) != 0 {
		t.Errorf("a record not kept lists %+v, want a snapshot held listing nothing", listed)
	}
	var none *cverecord.Snapshot
	if listed := none.Files([]string{"CVE-2024-26600"}); listed.Held {
		t.Error("no snapshot reads as one held")
	}
}

func TestEveryEntrysFilesAreJoinedInOneSpelling(t *testing.T) {
	doc := map[string][]byte{
		"CVE-2023-52603.json": published("CVE-2023-52603", "PUBLISHED", "2026-11-18T00:00:00Z",
			filesEntry("fs/jfs/jfs_dtree.c", "./fs/jfs//jfs_dtree.c", "tools/perf/../../fs/jfs/jfs_dtree.c"),
			filesEntry("/fs/jfs/jfs_txnmgr.c ", "")),
	}
	listed := built(t, listArchive(t, doc)).Files([]string{"CVE-2023-52603"})
	want := []string{"fs/jfs/jfs_dtree.c", "fs/jfs/jfs_txnmgr.c"}
	if !slices.Equal(listed.Files, want) {
		t.Errorf("read %v, want %v", listed.Files, want)
	}
}

func TestAListLeavingTheTreeOrPastABoundListsNothing(t *testing.T) {
	cverecord.LowerBounds(t, cverecord.Bounds{Files: 3, FileLength: 20, FileBytes: 16})
	snapshot := built(t, listArchive(t, map[string][]byte{
		"CVE-2026-10.json": published("CVE-2026-10", "PUBLISHED", "2026-11-18T00:00:00Z",
			filesEntry("drivers/y.c", "tools/perf/../../../drivers/x.c")),
		"CVE-2026-11.json": published("CVE-2026-11", "PUBLISHED", "2026-11-18T00:00:00Z",
			filesEntry("a.c", "b.c", "c.c", "d.c")),
		"CVE-2026-12.json": published("CVE-2026-12", "PUBLISHED", "2026-11-18T00:00:00Z",
			filesEntry("drivers/a-very-long-name.c")),
		"CVE-2026-13.json": published("CVE-2026-13", "PUBLISHED", "2026-11-18T00:00:00Z",
			filesEntry("a.c", "b.c")),
		// Three files of seven bytes, within the count and each within the
		// length, joined past sixteen bytes.
		"CVE-2026-14.json": published("CVE-2026-14", "PUBLISHED", "2026-11-18T00:00:00Z",
			filesEntry("one/a.c", "two/b.c", "six/c.c")),
		"CVE-2026-15.json": published("CVE-2026-15", "PUBLISHED", "2026-11-18T00:00:00Z",
			filesEntry("a.c", "b\nc.c")),
	}))
	for _, id := range []string{"CVE-2026-10", "CVE-2026-11", "CVE-2026-12", "CVE-2026-14", "CVE-2026-15"} {
		if listed := snapshot.Files([]string{id}); len(listed.Files) != 0 {
			t.Errorf("%s lists %v, want nothing", id, listed.Files)
		}
	}
	// The control: a list inside both bounds is read.
	if listed := snapshot.Files([]string{"CVE-2026-13"}); len(listed.Files) != 2 {
		t.Errorf("a list within the bounds reads %v", listed.Files)
	}
}

func TestADirectoryHoldsWholeSegments(t *testing.T) {
	for _, each := range []struct {
		file, directory string
		under           bool
	}{
		{"tools/perf/builtin-top.c", "tools/perf", true},
		{"tools/perf", "tools/perf", true},
		{"tools/perfect.c", "tools/perf", false},
		{"drivers/phy/ti/phy-omap-usb2.c", "tools/perf", false},
		{"anything.c", "", true},
	} {
		if got := cverecord.Under(each.file, each.directory); got != each.under {
			t.Errorf("%q under %q is %v, want %v", each.file, each.directory, got, each.under)
		}
	}
}
