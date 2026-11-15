// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordsRun runs the program with the CVE record directory set to dir and
// answers what it printed and what it returned.
func recordsRun(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	out, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = quiet.Close() }()
	ran := run(args, []string{"OPENPSIRT_RECORDS_DIR=" + dir}, out, quiet)
	printed, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(printed), ran
}

// cveListArchive writes an archive the way the CVE List publishes one, a zip
// holding cves.zip, with one published record in it that states a version
// unaffected, which is what a snapshot keeps.
func cveListArchive(t *testing.T) string {
	t.Helper()
	var inner bytes.Buffer
	w := zip.NewWriter(&inner)
	f, err := w.Create("cves/2026/31xxx/CVE-2026-31001.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(`{"cveMetadata":{"cveId":"CVE-2026-31001","state":"PUBLISHED",` +
		`"dateUpdated":"2026-10-01T00:00:00Z"},"containers":{"cna":{"affected":[` +
		`{"vendor":"Linux","product":"Linux","defaultStatus":"affected",` +
		`"versions":[{"version":"6.14","status":"affected"},` +
		`{"version":"6.18.27","lessThanOrEqual":"6.18.*","status":"unaffected","versionType":"semver"}]}]}}}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "2026-10-07_all_CVEs_at_midnight.zip.zip")
	file, err := os.Create(path) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	outer := zip.NewWriter(file)
	member, err := outer.CreateHeader(&zip.FileHeader{Name: "cves.zip", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := outer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRecordsStatusSaysNothingIsHeldInAnEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	printed, err := recordsRun(t, dir, "records", "status")
	if err != nil {
		t.Fatalf("records status over an empty directory failed: %v", err)
	}
	if want := "No CVE record snapshot in " + dir + "\n"; printed != want {
		t.Errorf("records status printed %q, want %q", printed, want)
	}
}

func TestRecordsImportPlacesASnapshotThatStatusThenReports(t *testing.T) {
	dir := t.TempDir()
	printed, err := recordsRun(t, dir, "records", "import", cveListArchive(t))
	if err != nil {
		t.Fatalf("records import of a published archive failed: %v", err)
	}
	if want := "CVE record snapshot taken 2026-10-01T00:00:00Z, 1 records, in " + dir + "\n"; printed != want {
		t.Errorf("records import printed %q, want %q", printed, want)
	}
	status, err := recordsRun(t, dir, "records", "status")
	if err != nil {
		t.Fatalf("records status after an import failed: %v", err)
	}
	if status != printed {
		t.Errorf("records status printed %q after an import that printed %q", status, printed)
	}
}

func TestRecordsRefusesAnActionOrOperandItDoesNotTake(t *testing.T) {
	for _, c := range []struct {
		args    []string
		refusal string
	}{
		{[]string{"records", "import"}, "openpsirt records import: name the CVE List archive to read"},
		{[]string{"records", "import", "a.zip", "b.zip"}, `openpsirt records: unexpected argument "b.zip"`},
		{[]string{"records", "status", "extra"}, `openpsirt records: unexpected argument "extra"`},
		{[]string{"records", "frob"}, `openpsirt records: unknown action "frob"`},
	} {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			dir := t.TempDir()
			printed, err := recordsRun(t, dir, c.args...)
			if err == nil || !strings.Contains(err.Error(), c.refusal) {
				t.Errorf("%q answered %v, want a refusal saying %q", c.args, err, c.refusal)
			}
			if printed != "" {
				t.Errorf("%q was refused and printed %q", c.args, printed)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Errorf("%q was refused and wrote %d files into the record directory", c.args, len(entries))
			}
		})
	}
}
