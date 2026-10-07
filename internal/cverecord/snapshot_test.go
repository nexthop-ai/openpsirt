// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// published is a CVE record as the List publishes it, cut to what is read.
func published(id, state, updated string, affected ...map[string]any) []byte {
	doc := map[string]any{
		"cveMetadata": map[string]any{"cveId": id, "state": state, "dateUpdated": updated},
		"containers":  map[string]any{"cna": map[string]any{"affected": affected}},
	}
	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return out
}

// listArchive writes an archive the way the List publishes one: a zip holding
// cves.zip, which holds a file per record.
func listArchive(t *testing.T, records map[string][]byte) string {
	t.Helper()
	var inner bytes.Buffer
	w := zip.NewWriter(&inner)
	for name, body := range records {
		f, err := w.Create("cves/2026/31xxx/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "2026-10-07_all_CVEs_at_midnight.zip.zip")
	out, err := os.Create(path) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	outer := zip.NewWriter(out)
	f, err := outer.Create("cves.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := outer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

var kernelEntry = map[string]any{
	"vendor": "Linux", "product": "Linux", "defaultStatus": "affected",
	"versions": []map[string]any{
		{"version": "6.14", "status": "affected"},
		{"version": "6.18.27", "lessThanOrEqual": "6.18.*", "status": "unaffected", "versionType": "semver"},
		{"version": "fb7d3bc4", "lessThan": "efc52947", "status": "affected", "versionType": "git"},
	},
}

func TestAnArchiveKeepsOnlyRecordsThatCanNarrow(t *testing.T) {
	archive := listArchive(t, map[string][]byte{
		"CVE-2026-31589.json": published("CVE-2026-31589", "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry),
		// Affected lines only: nothing in it could ever narrow a match.
		"CVE-2026-1.json": published("CVE-2026-1", "PUBLISHED", "2026-10-07T01:00:00Z", map[string]any{
			"vendor": "x", "product": "y",
			"versions": []map[string]any{{"version": "1.0", "lessThan": "2.0", "status": "affected"}},
		}),
		// Withdrawn.
		"CVE-2026-2.json": published("CVE-2026-2", "REJECTED", "2026-10-07T02:00:00Z", kernelEntry),
		"README.md":       []byte("not a record"),
	})
	dir := t.TempDir()
	if err := cverecord.Build(archive, dir, ""); err != nil {
		t.Fatal(err)
	}
	snapshot, err := cverecord.NewHeld(dir).Current()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Len() != 1 {
		t.Fatalf("kept %d records, want only the one with an unaffected line it can order", snapshot.Len())
	}
	// The newest moment any record read was updated, the withdrawn one
	// included: withdrawing a record changes what the snapshot narrows.
	if snapshot.Version() != "2026-10-07T02:00:00Z" {
		t.Errorf("taken %q, want the withdrawn record's update", snapshot.Version())
	}
	if !snapshot.Decide([]string{"CVE-2026-31589"}, kernel("6.18.55")).Narrows() {
		t.Error("the kept record does not narrow what it states")
	}
	// Nothing of the inner archive is left beside the snapshot.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != cverecord.FileName {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("the directory holds %v, want the snapshot alone", names)
	}
}

func TestAThirdPartysAffectedLineStopsTheAuthoritysNarrowing(t *testing.T) {
	// A third party adds its own entries beside the numbering authority's,
	// and they are part of the record.
	doc := map[string]any{
		"cveMetadata": map[string]any{"cveId": "CVE-2026-5", "state": "PUBLISHED",
			"dateUpdated": "2026-10-07T00:00:00Z"},
		"containers": map[string]any{
			"cna": map[string]any{"affected": []map[string]any{{
				"vendor": "zlib", "product": "zlib", "cpes": []string{"cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"},
				"versions": []map[string]any{
					{"version": "1.3.1", "lessThanOrEqual": "1.3.*", "status": "unaffected", "versionType": "semver"},
				},
			}}},
			"adp": []map[string]any{{"affected": []map[string]any{{
				"vendor": "zlib", "product": "zlib", "cpes": []string{"cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*"},
				"versions": []map[string]any{
					{"version": "0", "lessThan": "2.5", "status": "affected", "versionType": "semver"},
				},
			}}}},
		},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := cverecord.Build(listArchive(t, map[string][]byte{"CVE-2026-5.json": body}), dir, ""); err != nil {
		t.Fatal(err)
	}
	snapshot, err := cverecord.NewHeld(dir).Current()
	if err != nil {
		t.Fatal(err)
	}
	zlib := graph.Described{Name: "zlib", Version: "1.3.2", Purl: "pkg:generic/zlib@1.3.2",
		CPE: "cpe:2.3:a:zlib:zlib:1.3.2:*:*:*:*:*:*:*"}
	if snapshot.Decide([]string{"CVE-2026-5"}, zlib).Narrows() {
		t.Error("a release a third party's entry states is affected was narrowed")
	}
}

func TestAnArchiveHoldingNoRecordsIsRefused(t *testing.T) {
	archive := listArchive(t, map[string][]byte{"README.md": []byte("nothing")})
	if err := cverecord.Build(archive, t.TempDir(), ""); err == nil {
		t.Error("an archive with no records built a snapshot")
	}
}

func TestTheSnapshotHeldIsReadAgainOnceItIsReplaced(t *testing.T) {
	dir := t.TempDir()
	write := func(records ...cverecord.Record) {
		t.Helper()
		f, err := os.CreateTemp(dir, "next")
		if err != nil {
			t.Fatal(err)
		}
		if err := cverecord.Write(f, time.Now(), "", records); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if err := os.Rename(f.Name(), filepath.Join(dir, cverecord.FileName)); err != nil {
			t.Fatal(err)
		}
	}
	held := cverecord.NewHeld(dir)
	if none, err := held.Current(); none != nil || err != nil {
		t.Fatalf("an empty directory answered %v, %v, want no snapshot and no error", none, err)
	}
	write(fixedOnTheBranch)
	first, err := held.Current()
	if err != nil || first.Len() != 1 {
		t.Fatalf("read %v records, %v", first.Len(), err)
	}
	write(fixedOnTheBranch, introducedOnTheBranch)
	second, err := held.Current()
	if err != nil || second.Len() != 2 {
		t.Fatalf("after replacing it, read %v records, %v, want 2", second.Len(), err)
	}
}

func TestADamagedSnapshotIsAnErrorRatherThanNoRecords(t *testing.T) {
	// A scan that narrowed nothing because a bundle was damaged would read as
	// records that excluded nothing.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cverecord.FileName), []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := cverecord.NewHeld(dir).Current(); err == nil {
		t.Error("a damaged snapshot read as none")
	}
}

func TestASnapshotInAnotherFormatIsRefused(t *testing.T) {
	var written bytes.Buffer
	zipped := gzip.NewWriter(&written)
	if _, err := zipped.Write([]byte(`{"format":2,"taken":"2026-10-07T00:00:00Z","records":0}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := zipped.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := cverecord.Read(&written)
	if err == nil || !strings.Contains(err.Error(), "format 2") {
		t.Errorf("a snapshot in format 2 answered %v, want a refusal naming it", err)
	}
}
