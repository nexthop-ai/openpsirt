// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord_test

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/bound/boundtest"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
)

// taken is the moment every snapshot here describes.
var taken = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

// recordSized is a record whose snapshot line, newline included, is n bytes.
func recordSized(t *testing.T, n int) cverecord.Record {
	t.Helper()
	empty, err := json.Marshal(cverecord.Record{})
	if err != nil {
		t.Fatal(err)
	}
	pad := n - len(empty) - 1
	if pad < 0 {
		t.Fatalf("no record has a line of %d bytes", n)
	}
	return cverecord.Record{ID: strings.Repeat("A", pad)}
}

// records is n records with distinct identifiers.
func records(n int) []cverecord.Record {
	out := make([]cverecord.Record, n)
	for i := range out {
		out[i] = cverecord.Record{ID: fmt.Sprintf("CVE-2026-%d", i+1)}
	}
	return out
}

// writeThenRead writes records and reads them back, and fails the test where
// what was written cannot be read.
func writeThenRead(t *testing.T, rows []cverecord.Record) error {
	t.Helper()
	var buf bytes.Buffer
	if err := cverecord.Write(&buf, taken, "", rows); err != nil {
		return err
	}
	if _, err := cverecord.Read(&buf); err != nil {
		t.Fatalf("a snapshot written here cannot be read: %v", err)
	}
	return nil
}

// headerLen is how many bytes Write spends on a snapshot's first line.
func headerLen(t *testing.T) int {
	t.Helper()
	var buf bytes.Buffer
	if err := cverecord.Write(&buf, taken, "", nil); err != nil {
		t.Fatal(err)
	}
	unzipped, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(unzipped)
	if err != nil {
		t.Fatal(err)
	}
	return len(raw)
}

// zipped is lines gzipped, the way a snapshot is carried.
func zipped(t *testing.T, lines ...string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	for _, line := range lines {
		if _, err := w.Write([]byte(line + "\n")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

const snapshotHead = `{"format":1,"taken":"2026-10-07T00:00:00Z","records":0}`

func TestASnapshotWrittenHereHoldsNoMoreRecordsThanOneRead(t *testing.T) {
	cverecord.LowerBounds(t, cverecord.Bounds{Records: 3})
	boundtest.Edges(t, 3, func(n int) error { return writeThenRead(t, records(n)) }, cverecord.IsTooLarge)
}

func TestASnapshotWrittenHereHoldsNoLongerLineThanOneRead(t *testing.T) {
	const line = 4096
	cverecord.LowerBounds(t, cverecord.Bounds{Line: line})
	boundtest.Edges(t, line, func(n int) error {
		return writeThenRead(t, []cverecord.Record{recordSized(t, n)})
	}, cverecord.IsTooLarge)
}

func TestASnapshotWrittenHereIsNoLargerThanOneRead(t *testing.T) {
	most := headerLen(t) + 4096
	cverecord.LowerBounds(t, cverecord.Bounds{SnapshotBytes: int64(most)})
	boundtest.Edges(t, most, func(n int) error {
		return writeThenRead(t, []cverecord.Record{recordSized(t, n-headerLen(t))})
	}, cverecord.IsTooLarge)
}

func TestReadingASnapshotRefusesMoreRecordsThanTheBound(t *testing.T) {
	cverecord.LowerBounds(t, cverecord.Bounds{Records: 3})
	boundtest.Edges(t, 3, func(n int) error {
		lines := []string{snapshotHead}
		for i := range n {
			lines = append(lines, fmt.Sprintf(`{"id":"CVE-2026-%d"}`, i+1))
		}
		_, err := cverecord.Read(zipped(t, lines...))
		return err
	}, cverecord.IsTooLarge)
}

func TestReadingASnapshotRefusesALineLongerThanTheBound(t *testing.T) {
	const line = 4096
	cverecord.LowerBounds(t, cverecord.Bounds{Line: line})
	boundtest.Edges(t, line, func(n int) error {
		// A line of n bytes, newline included.
		pad := n - 1 - len(`{"id":""}`)
		_, err := cverecord.Read(zipped(t, snapshotHead, `{"id":"`+strings.Repeat("A", pad)+`"}`))
		return err
	}, cverecord.IsTooLarge)
}

func TestReadingASnapshotRefusesMoreBytesThanTheBound(t *testing.T) {
	// An operator's bundle is a file from outside: a few records of long
	// lines of one repeated string compress to almost nothing and decompress
	// into all the memory there is.
	most := len(snapshotHead) + 1 + 4096
	cverecord.LowerBounds(t, cverecord.Bounds{SnapshotBytes: int64(most)})
	boundtest.Edges(t, most, func(n int) error {
		pad := n - (len(snapshotHead) + 1) - 1 - len(`{"id":""}`)
		_, err := cverecord.Read(zipped(t, snapshotHead, `{"id":"`+strings.Repeat("A", pad)+`"}`))
		return err
	}, cverecord.IsTooLarge)
}

func TestAnArchiveKeepingMoreThanASnapshotHoldsBuildsNothing(t *testing.T) {
	// What an archive keeps is held in memory until it is written, so it is
	// bounded by what a snapshot holds before the snapshot is written.
	cverecord.LowerBounds(t, cverecord.Bounds{Records: 2})
	boundtest.Edges(t, 2, func(n int) error {
		files := map[string][]byte{}
		for i := range n {
			id := fmt.Sprintf("CVE-2026-%d", i+1)
			files[id+".json"] = published(id, "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry)
		}
		_, _, err := cverecord.FromArchive(listArchive(t, files), t.TempDir())
		return err
	}, cverecord.IsTooLarge)
}

func TestARecordLargerThanASnapshotHoldsLeavesTheSnapshotHeld(t *testing.T) {
	// A record the archive admits and a snapshot cannot hold fails the
	// build before the rename, so the snapshot a scan reads stays the last
	// good one rather than one that stalls every scan.
	dir := t.TempDir()
	first := listArchive(t, map[string][]byte{
		"CVE-2026-31589.json": published("CVE-2026-31589", "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry),
	})
	if err := cverecord.Build(first, dir, "first"); err != nil {
		t.Fatal(err)
	}
	cverecord.LowerBounds(t, cverecord.Bounds{Line: 512})
	long := map[string]any{"vendor": strings.Repeat("v", 1024), "product": "p", "versions": kernelEntry["versions"]}
	second := listArchive(t, map[string][]byte{
		"CVE-2026-31589.json": published("CVE-2026-31589", "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry),
		"CVE-2026-43465.json": published("CVE-2026-43465", "PUBLISHED", "2026-10-07T00:40:00Z", long),
	})
	if err := cverecord.Build(second, dir, "second"); !cverecord.IsTooLarge(err) {
		t.Fatalf("building past the bound answered %v, want a refusal", err)
	}
	held, err := cverecord.NewHeld(dir).Current()
	if err != nil || held.Len() != 1 {
		t.Fatalf("the snapshot held is %v, %v; want the first build's", held, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("a refused build left %d files in the directory", len(entries))
	}
}

// zipOf writes an archive of n empty members and a comment, and names it.
func zipOf(t *testing.T, n int, comment string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "members.zip")
	f, err := os.Create(path) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for i := range n {
		if _, err := w.CreateHeader(&zip.FileHeader{Name: fmt.Sprint(i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.SetComment(comment); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAnArchiveWithMoreMembersThanTheBoundIsRefusedBeforeItIsOpened(t *testing.T) {
	cverecord.LowerBounds(t, cverecord.Bounds{Members: 3})
	boundtest.Edges(t, 3, func(n int) error { return cverecord.CountMembers(zipOf(t, n, "a comment")) },
		cverecord.IsTooLarge)
}

func TestAMemberCountPastSixteenBitsIsReadFromTheZip64Directory(t *testing.T) {
	// Past 65,535 members the directory end defers to the zip64 record, and
	// it is the zip64 record that says where the directory starts.
	if testing.Short() {
		t.Skip("writes two archives of seventy thousand members")
	}
	const most = 70_000
	cverecord.LowerBounds(t, cverecord.Bounds{Members: most})
	boundtest.Edges(t, most, func(n int) error { return cverecord.CountMembers(zipOf(t, n, "")) },
		cverecord.IsTooLarge)
}

func TestAZip64ArchiveBehindOtherDataIsCountedFromWhereAReaderStarts(t *testing.T) {
	// Data before an archive moves every offset in it. A zip64 archive whose
	// locator was corrected for the data is opened by a reader, which starts
	// the directory from the zip64 record rather than the directory end.
	if testing.Short() {
		t.Skip("writes an archive of seventy thousand members")
	}
	const most = 70_000
	cverecord.LowerBounds(t, cverecord.Bounds{Members: most})
	raw, err := os.ReadFile(zipOf(t, most+1, "")) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	const prefix = 100
	locus := bytes.LastIndex(raw, []byte("PK\x06\x07"))
	at := binary.LittleEndian.Uint64(raw[locus+8:])
	binary.LittleEndian.PutUint64(raw[locus+8:], at+prefix)
	path := filepath.Join(t.TempDir(), "behind.zip")
	if err := os.WriteFile(path, append(bytes.Repeat([]byte{0}, prefix), raw...), 0o600); err != nil { //nolint:gosec // G703: a path under the test's own directory
		t.Fatal(err)
	}
	opened, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("a reader does not open the archive, so it tests nothing: %v", err)
	}
	if len(opened.File) != most+1 {
		t.Fatalf("a reader found %d members", len(opened.File))
	}
	_ = opened.Close()
	if err := cverecord.CountMembers(path); !cverecord.IsTooLarge(err) {
		t.Errorf("the archive answered %v, want a refusal", err)
	}
}

func TestAMemberCountWalksPastTheCountTheDirectoryEndStates(t *testing.T) {
	// The directory end's count is compared by a reader in its low sixteen
	// bits only, so an archive stating one member and holding many more is
	// opened whole. The count is of the entries a reader walks.
	cverecord.LowerBounds(t, cverecord.Bounds{Members: 3})
	path := zipOf(t, 4, "")
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	end := bytes.LastIndex(raw, []byte("PK\x05\x06"))
	raw[end+8], raw[end+9], raw[end+10], raw[end+11] = 1, 0, 1, 0
	if err := os.WriteFile(path, raw, 0o600); err != nil { //nolint:gosec // G703: a path under the test's own directory
		t.Fatal(err)
	}
	if err := cverecord.CountMembers(path); !cverecord.IsTooLarge(err) {
		t.Errorf("an archive understating its members answered %v, want a refusal", err)
	}
}

func TestAnArchiveRecordLargerThanTheBoundIsRefused(t *testing.T) {
	body := published("CVE-2026-31589", "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry)
	most := len(body) + 64
	cverecord.LowerBounds(t, cverecord.Bounds{Record: uint64(most)})
	boundtest.Edges(t, most, func(n int) error {
		padded := append(append([]byte{}, body...), bytes.Repeat([]byte(" "), n-len(body))...)
		_, _, err := cverecord.FromArchive(listArchive(t, map[string][]byte{"CVE-2026-31589.json": padded}),
			t.TempDir())
		return err
	}, cverecord.IsTooLarge)
}

// innerSized writes a List archive whose inner archive is n bytes, padded by
// its comment, and names it.
func innerSized(t *testing.T, n int) string {
	t.Helper()
	inner := func(comment string) []byte {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, err := w.Create("cves/2026/31xxx/CVE-2026-31589.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(published("CVE-2026-31589", "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry)); err != nil {
			t.Fatal(err)
		}
		if err := w.SetComment(comment); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	bare := len(inner(""))
	if n < bare {
		t.Fatalf("no inner archive is %d bytes", n)
	}
	body := inner(strings.Repeat("c", n-bare))
	path := filepath.Join(t.TempDir(), "list.zip")
	out, err := os.Create(path) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(out)
	f, err := w.Create("cves.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAnInnerArchiveLargerThanTheBoundIsRefusedAndRemoved(t *testing.T) {
	most := 2048
	cverecord.LowerBounds(t, cverecord.Bounds{Inner: int64(most)})
	boundtest.Edges(t, most, func(n int) error {
		scratch := t.TempDir()
		_, _, err := cverecord.FromArchive(innerSized(t, n), scratch)
		if left, _ := filepath.Glob(filepath.Join(scratch, ".cves-*")); len(left) > 0 {
			t.Fatalf("the inner archive was left behind: %v", left)
		}
		return err
	}, cverecord.IsTooLarge)
}

func TestADownloadLargerThanTheBoundIsRefusedAndRemoved(t *testing.T) {
	archive := listArchive(t, map[string][]byte{
		"CVE-2026-31589.json": published("CVE-2026-31589", "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry),
	})
	raw, err := os.ReadFile(archive) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	most := len(raw)
	cverecord.LowerBounds(t, cverecord.Bounds{Archive: int64(most)})
	boundtest.Edges(t, most, func(n int) error {
		// Bytes past the archive's own are taken by a zip reader as data
		// before the archive, so the download is padded at the front.
		padded := filepath.Join(t.TempDir(), "padded.zip")
		if err := os.WriteFile(padded, append(bytes.Repeat([]byte{0}, n-most), raw...), 0o600); err != nil { //nolint:gosec // G703: a path under the test's own directory
			t.Fatal(err)
		}
		l := &list{tag: "cve_2026-10-07_0500Z", archives: map[string]string{
			"2026-10-07_all_CVEs_at_midnight.zip.zip": padded,
		}}
		dir := t.TempDir()
		_, err := fetcherFor(t, l.serve(t), dir).Once(t.Context())
		if left, _ := filepath.Glob(filepath.Join(dir, ".archive-*")); len(left) > 0 {
			t.Fatalf("the download was left behind: %v", left)
		}
		return err
	}, cverecord.IsTooLarge)
}
