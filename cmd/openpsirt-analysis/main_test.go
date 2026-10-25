// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const output = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"lint","version":"1"}},` +
	`"results":[{"ruleId":"r1","message":{"text":"m"},"locations":[{"physicalLocation":` +
	`{"artifactLocation":{"uri":"file.c"},"region":{"startLine":1}}}]}]}]}`

// checkout is a git repository holding one file, and an analyzer's SARIF
// about it beside the repository.
func checkout(t *testing.T) (root, sarif string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file.c"), []byte("int x;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.email=b@example.com", "-c", "user.name=B", "add", "file.c"},
		{"-c", "user.email=b@example.com", "-c", "user.name=B", "commit", "-q", "-m", "first"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil { //nolint:gosec // G204: the test's own arguments
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	sarif = filepath.Join(t.TempDir(), "lint.sarif")
	if err := os.WriteFile(sarif, []byte(output), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	return root, sarif
}

// deployment answers every upload and counts what reached it.
func deployment(t *testing.T) (*httptest.Server, *[]*http.Request) {
	t.Helper()
	var got []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"queued"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func upload(url string, rest ...string) []string {
	return append([]string{"upload", "--url", url, "--product", "p", "--stream", "s", "--variant", "v", "--series", "lint"}, rest...)
}

func TestTheKeyIsReadFromTheEnvironmentAlone(t *testing.T) {
	_, sarif := checkout(t)
	srv, got := deployment(t)
	t.Setenv("OPENPSIRT_KEY", "")
	if err := run(context.Background(), upload(srv.URL, sarif), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("an upload with no key was sent")
	}
	if err := run(context.Background(), upload(srv.URL, "--key", "k", sarif), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("a key on the command line was accepted")
	}
	if len(*got) != 0 {
		t.Fatalf("%d requests reached the deployment without a key", len(*got))
	}

	t.Setenv("OPENPSIRT_KEY", "secret")
	var stdout bytes.Buffer
	if err := run(context.Background(), upload(srv.URL, sarif), &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 1 || (*got)[0].Header.Get("Authorization") != "Bearer secret" {
		t.Fatalf("sent %d requests; want one carrying the key", len(*got))
	}
	if !strings.Contains(stdout.String(), "queued") {
		t.Errorf("printed %q; want the receipt", stdout.String())
	}
}

func TestADirectoryOfOutputIsRefused(t *testing.T) {
	checkout(t)
	err := run(context.Background(), []string{"write", "--series", "lint", "--output", "x", t.TempDir()}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "HTML reports") {
		t.Fatalf("refused with %v; want a directory named", err)
	}
}

func TestTheSaltIsNamedByItsTrimmedBytes(t *testing.T) {
	_, sarif := checkout(t)
	salt := filepath.Join(t.TempDir(), "salt")
	if err := os.WriteFile(salt, []byte("  pepper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.sarif")
	if err := run(context.Background(), []string{"write", "--series", "lint", "--salt-file", salt, "--output", out, sarif},
		&bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(out) //nolint:gosec // G304: a path under the test's own directory
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("pepper"))
	if want := `"openpsirt/salt":"` + hex.EncodeToString(sum[:8]) + `"`; !bytes.Contains(doc, []byte(want)) {
		t.Errorf("the document does not carry %s", want)
	}
	if bytes.Contains(doc, []byte("pepper")) {
		t.Error("the document carries the salt itself")
	}
}

// second is a second analyzer's output about the checkout's file.
func second(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "check.sarif")
	if err := os.WriteFile(path, []byte(strings.Replace(output, `"name":"lint"`, `"name":"check"`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheOutputOfTwoAnalyzersIsAnUploadOfEach(t *testing.T) {
	_, sarif := checkout(t)
	srv, got := deployment(t)
	t.Setenv("OPENPSIRT_KEY", "secret")
	args := []string{"upload", "--url", srv.URL, "--product", "p", "--stream", "s", "--variant", "v",
		"--series", "lint=lint/all", "--series", "check=check/all", sarif, second(t)}
	if err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(*got) != 2 {
		t.Fatalf("sent %d uploads; want one per analyzer", len(*got))
	}
}

func TestTheOutputOfTwoAnalyzersIsWrittenToAFileOfEach(t *testing.T) {
	_, sarif := checkout(t)
	out := filepath.Join(t.TempDir(), "run.sarif")
	if err := run(context.Background(), []string{"write", "--series", "lint=lint/all", "--series", "check=check/all",
		"--output", out, sarif, second(t)}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"lint", "check"} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(out), "run."+tool+".sarif")) //nolint:gosec // G304: a path under the test's own directory
		if err != nil || !strings.Contains(string(data), tool+"/all") {
			t.Errorf("%s's document: %v; want its own file naming its series", tool, err)
		}
	}
}

func TestOneAnalyzersRulesAreRefusedForTheOutputOfTwo(t *testing.T) {
	_, sarif := checkout(t)
	srv, got := deployment(t)
	t.Setenv("OPENPSIRT_KEY", "secret")
	args := []string{"upload", "--url", srv.URL, "--product", "p", "--stream", "s", "--variant", "v",
		"--series", "lint=lint/all", "--series", "check=check/all", "--rule", "r1", sarif, second(t)}
	if err := run(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil || len(*got) != 0 {
		t.Errorf("err %v, %d sent; want the rules refused before anything is sent", err, len(*got))
	}
}
