// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repository makes a git repository whose first commit holds files, and
// returns its directory.
func repository(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		full := append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com",
			"-c", "commit.gpgsign=false"}, args...)
		if out, err := exec.Command("git", full...).CombinedOutput(); err != nil { //nolint:gosec // G204: git, over a repository this test made
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q", "-b", "main")
	write(t, dir, files)
	git("add", "-A")
	git("commit", "-q", "--allow-empty", "-m", "base")
	return dir
}

func write(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, text := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAFileTheBaseLacksReadsAsEmptyWhereverItIsOnDisk(t *testing.T) {
	dir := repository(t, map[string]string{"kept": "held\n"})
	write(t, dir, map[string]string{"go.mod": "module m\n", "web/package-lock.json": "{}"})
	for _, file := range []string{"go.mod", "web/package-lock.json", "gone"} {
		got, err := at(dir, "HEAD", file)
		if err != nil || got != nil {
			t.Errorf("%s, absent from the base: read %q, %v; want nothing and no error", file, got, err)
		}
	}
	if got, err := at(dir, "HEAD", "kept"); err != nil || string(got) != "held\n" {
		t.Errorf("a file the base holds read as %q, %v", got, err)
	}
	if _, err := at(t.TempDir(), "HEAD", "go.mod"); err == nil {
		t.Error("a directory that is no repository read as a base without the file")
	}
}

// goStream is govulncheck's output for a module at v1.1.0 carrying GO-OLD,
// which v1.0.0 already had, and GO-NEW, which v1.0.0 did not.
const goStream = `{"config":{"scanner_name":"govulncheck"}}
{"SBOM":{"modules":[{"path":"example.com/m","version":"v1.1.0"}]}}
{"osv":{"id":"GO-OLD","affected":[{"package":{"name":"example.com/m"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}}
{"osv":{"id":"GO-NEW","affected":[{"package":{"name":"example.com/m"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.1.0"}]}]}]}}
{"finding":{"osv":"GO-OLD","trace":[{"module":"example.com/m","version":"v1.1.0","function":"F"}]}}
{"finding":{"osv":"GO-NEW","trace":[{"module":"example.com/m","version":"v1.1.0","function":"F"}]}}
`

func TestTheGoHalfFailsOnlyWhatTheBaseDidNotCarry(t *testing.T) {
	dir := repository(t, map[string]string{"go.mod": "module x\n\ngo 1.27.1\n\nrequire example.com/m v1.0.0\n"})
	write(t, dir, map[string]string{"stream.json": goStream})
	var out strings.Builder
	err := run(dir, "main", []string{"go", "--", "cat", "stream.json"}, &out)
	if !errors.Is(err, errFailed) {
		t.Fatalf("an introduced advisory did not fail the change: %v\n%s", err, out.String())
	}
	introduced, present, _ := strings.Cut(out.String(), "already on main")
	if !strings.Contains(introduced, "GO-NEW") || strings.Contains(introduced, "GO-OLD") {
		t.Errorf("GO-NEW alone is introduced:\n%s", out.String())
	}
	if !strings.Contains(present, "GO-OLD") {
		t.Errorf("GO-OLD, which the base carried, was not reported as present:\n%s", out.String())
	}
}

func TestTheGoHalfRefusesAScanOfNothing(t *testing.T) {
	dir := repository(t, map[string]string{"go.mod": "module x\n"})
	var out strings.Builder
	err := run(dir, "main", []string{"go", "--", "echo", `{"config":{}}`}, &out)
	if err == nil || errors.Is(err, errFailed) {
		t.Errorf("a scan that named no modules read as a scan: %v\n%s", err, out.String())
	}
}

const lock = `{"packages":{"":{},"node_modules/braces":{"version":"3.0.2"},"node_modules/x":{"version":"1.0.0"}}}`

func npmReport(names ...string) string {
	var parts []string
	for _, name := range names {
		parts = append(parts, `"`+name+`":{"via":[{"name":"`+name+`","title":"t","url":"https://github.com/advisories/GHSA-`+
			name+`","severity":"high"}],"nodes":["node_modules/`+name+`"]}`)
	}
	return `{"auditReportVersion":2,"vulnerabilities":{` + strings.Join(parts, ",") + `}}`
}

func TestTheNpmHalfFailsOnlyWhatTheBaseDidNotCarry(t *testing.T) {
	dir := repository(t, map[string]string{"web/package.json": "{}", "web/package-lock.json": lock})
	write(t, dir, map[string]string{
		"head.json": npmReport("braces", "x"),
		"base.json": npmReport("braces"),
	})
	// The scanner answers the head's audit in web/ and the base's anywhere
	// else, and refuses a run that would read the installed tree.
	script := `for a; do [ "$a" = --package-lock-only ] && ok=1; done
[ -n "$ok" ] || { echo "audited the installed tree" >&2; exit 9; }
case "$PWD" in */web) cat "$ROOT/head.json" ;; *) cat "$ROOT/base.json" ;; esac`
	t.Setenv("ROOT", dir)
	var out strings.Builder
	err := run(dir, "main", []string{"npm", "--", "sh", "-c", script, "npm"}, &out)
	if !errors.Is(err, errFailed) {
		t.Fatalf("an introduced advisory did not fail the change: %v\n%s", err, out.String())
	}
	introduced, present, _ := strings.Cut(out.String(), "already on main")
	if !strings.Contains(introduced, "GHSA-x") || strings.Contains(introduced, "GHSA-braces") {
		t.Errorf("GHSA-x alone is introduced:\n%s", out.String())
	}
	if !strings.Contains(present, "GHSA-braces") {
		t.Errorf("GHSA-braces, which the base carried, was not reported as present:\n%s", out.String())
	}
}

func TestTheNpmHalfRefusesAnEmptyLockfile(t *testing.T) {
	dir := repository(t, map[string]string{"web/package-lock.json": `{"packages":{"":{}}}`})
	var out strings.Builder
	err := run(dir, "main", []string{"npm", "--", "echo", npmReport()}, &out)
	if err == nil || errors.Is(err, errFailed) {
		t.Errorf("a lockfile of no packages read as a scan: %v", err)
	}
}

// stdlibStream is govulncheck's output for a standard-library advisory fixed
// in Go 1.27.4.
const stdlibStream = `{"config":{"scanner_name":"govulncheck"}}
{"SBOM":{"modules":[{"path":"stdlib","version":"v1.27.3"}]}}
{"osv":{"id":"GO-STD","affected":[{"package":{"name":"stdlib"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.27.4"}]}]}]}}
{"finding":{"osv":"GO-STD","trace":[{"module":"stdlib","version":"v1.27.3","function":"F"}]}}
`

func TestTheStandardLibraryIsTheReleaseTheBaseImageBuildsWith(t *testing.T) {
	const mod = "module x\n\ngo 1.27.1\n"
	for _, c := range []struct {
		what, dockerfile string
		introduced       bool
	}{
		{"a base image already fixed, which the change moves back", "FROM golang:1.27.4-alpine AS build\n", true},
		{"a base image already affected", "FROM golang:1.27.3-alpine AS build\n", false},
		{"a base naming no image, read from the go line", "", false},
	} {
		files := map[string]string{"go.mod": mod}
		if c.dockerfile != "" {
			files["Dockerfile"] = c.dockerfile
		}
		dir := repository(t, files)
		write(t, dir, map[string]string{"stream.json": stdlibStream})
		var out strings.Builder
		err := run(dir, "main", []string{"go", "--", "cat", "stream.json"}, &out)
		if got := errors.Is(err, errFailed); got != c.introduced {
			t.Errorf("%s: failed %v, want %v: %v\n%s", c.what, got, c.introduced, err, out.String())
		}
	}
}
