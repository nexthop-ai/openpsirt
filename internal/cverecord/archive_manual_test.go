// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// TestAgainstARealArchive reads a CVE List archive somebody downloaded, and is
// skipped unless they point at one.
//
// Run with OPENPSIRT_CVE_ARCHIVE set to a day's `_all_CVEs_at_midnight.zip.zip`.
// It exists because what the List's records say is not something to assume:
// the kernel's records write a branch's fix as a wildcard bound, a commit
// range beside every release range, and the version a bug arrived in as a
// line with no type at all.
func TestAgainstARealArchive(t *testing.T) {
	archive := os.Getenv("OPENPSIRT_CVE_ARCHIVE")
	if archive == "" {
		t.Skip("set OPENPSIRT_CVE_ARCHIVE to a CVE List archive to read it")
	}
	dir := t.TempDir()
	if err := cverecord.Build(archive, dir, ""); err != nil {
		t.Fatal(err)
	}
	snapshot, err := cverecord.NewHeld(dir).Current()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Len() == 0 {
		t.Fatal("the archive kept no records, so this checked nothing")
	}
	t.Logf("kept %d records, taken %s", snapshot.Len(), snapshot.Version())
	if info, err := os.Stat(filepath.Join(dir, cverecord.FileName)); err == nil {
		t.Logf("snapshot is %d bytes", info.Size())
	}

	onie := graph.Described{
		Name: "linux", Version: "6.18.55", Purl: "pkg:generic/linux@6.18.55",
		CPE: "cpe:2.3:o:linux:linux_kernel:6.18.55:*:*:*:*:*:*:*",
	}
	sonic := graph.Described{
		Name: "linux-image-6.12.41+deb13-sonic-amd64-unsigned", Version: "6.12.41-1",
		UpstreamName: "linux",
		Purl:         "pkg:deb/debian/linux-image-6.12.41%2Bdeb13-sonic-amd64-unsigned@6.12.41-1?arch=amd64&distro=debian-13&upstream=linux",
	}
	grub := graph.Described{
		Name: "grub", Version: "2.14", Purl: "pkg:generic/grub@2.14",
		CPE: "cpe:2.3:a:gnu:grub2:2.14:*:*:*:*:*:*:*",
	}
	for _, each := range []struct {
		issue     string
		component graph.Described
		narrows   bool
	}{
		// Fixed on 6.18.y at 6.18.27; NVD's range runs to 6.19.14.
		{"CVE-2026-31589", onie, true},
		// Introduced on 6.12.y at 6.12.56.
		{"CVE-2026-43465", sonic, true},
		// A distribution's record whose upstream entry says 2.14 is affected.
		{"CVE-2025-61662", grub, false},
	} {
		verdict := snapshot.Decide([]string{each.issue}, each.component)
		if verdict.Narrows() != each.narrows {
			t.Errorf("%s in %s: narrows is %v, want %v (%+v)",
				each.issue, each.component.Name, verdict.Narrows(), each.narrows, verdict)
		}
	}
}
