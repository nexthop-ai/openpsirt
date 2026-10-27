// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/uploadclient"
)

// checkout is the reader fixtures' sources as a committed git checkout, with
// origin set to remote.
func checkout(t *testing.T, remote string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	dir := t.TempDir()
	from := filepath.Join("..", "sarif", "testdata", "src")
	for _, f := range []string{"a.c", "b.c", filepath.Join("include", "shared.h")} {
		data, err := os.ReadFile(filepath.Join(from, f)) //nolint:gosec // G304: a path under the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, f)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), data, 0o600); err != nil { //nolint:gosec // G703: a path under the test's own directory
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"}, {"add", "."},
		{"-c", "user.email=b@example.com", "-c", "user.name=B", "commit", "-q", "-m", "sources"},
		{"remote", "add", "origin", remote},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // G204: the test's own arguments
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return dir
}

// TestWhatTheClientWritesIsWhatTheDeploymentReads sends the client's run of
// two clang units through the reader and the placing a stored run is read
// with, so the two cannot come to disagree about a field.
func TestWhatTheClientWritesIsWhatTheDeploymentReads(t *testing.T) {
	root := checkout(t, "git@github.com:example/sonic.git")
	var inputs []uploadclient.Input
	for _, name := range []string{"clang18-a.plist", "clang18-b.plist"} {
		data, err := os.ReadFile(filepath.Join("..", "uploadclient", "testdata", name)) //nolint:gosec // G304: a path under the test's own directory
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, uploadclient.Input{Name: name, Data: data})
	}
	two, exit := 2, 0
	built := time.Date(2026, 10, 1, 2, 0, 0, 0, time.UTC)
	runs, _, err := uploadclient.Build(t.Context(), uploadclient.Options{
		Root: root, Work: root, Series: "clang-sa/default", Built: built,
		UnitsExpected: &two, ExitStatus: &exit, Client: "openpsirt-upload test",
	}, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("%d runs; want clang's alone", len(runs))
	}
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(bytes.NewReader(runs[0].Doc))
	if err != nil {
		t.Fatalf("the deployment refuses what the client wrote: %v", err)
	}

	stated := Describe([]sarif.Log{log}, Stated{})
	if stated.Series != "clang-sa/default" || !stated.BuiltAt.Equal(built) {
		t.Errorf("series %q built %v", stated.Series, stated.BuiltAt)
	}
	p := stated.Params
	if p.ToolName != "clang" || p.ClientVersion != "openpsirt-upload test" ||
		p.UnitsExpected == nil || *p.UnitsExpected != 2 || p.UnitsAnalyzed == nil || *p.UnitsAnalyzed != 2 ||
		p.ExitStatus == nil || *p.ExitStatus != 0 || p.Completed == nil || !*p.Completed {
		t.Errorf("parameters %+v", p)
	}

	placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := placed.Receipt.Dropped[DroppedOutside]; n != 0 {
		t.Errorf("%d results placed outside the checkout", n)
	}
	// The header's result is reported by both units and kept once.
	if len(placed.Results) != 4 || placed.Receipt.Dropped[DroppedRepeat] != 1 {
		t.Errorf("%d results, %v dropped; want four and the header's repeat", len(placed.Results), placed.Receipt.Dropped)
	}
	if len(placed.Modules) != 1 || placed.Modules[0].Remote != "https://github.com/example/sonic" || placed.Modules[0].Path != "" {
		t.Errorf("repositories %+v; want the checkout's own", placed.Modules)
	}
	var header *sarif.Placed
	for i, res := range placed.Results {
		if res.Path == "include/shared.h" {
			header = &placed.Results[i]
		}
		if res.Fingerprints["openpsirt/context/v1"] == "" || res.Fingerprints["clang/issueHash/v1"] == "" {
			t.Errorf("%s:%d carries %v; want the client's fingerprint and clang's", res.Path, res.StartLine, res.Fingerprints)
		}
	}
	if header == nil {
		t.Fatal("no result in the header")
	}
	if header.Function != "header_div" {
		t.Errorf("function %q", header.Function)
	}
	if got := chain(header.Steps); got != "leak → header_div" {
		t.Errorf("call chain %q; want leak → header_div", got)
	}
	k := key(ruleName(placed.Runs[0].Tool, header.RuleID), *header)
	if k.Scheme != "openpsirt/context/v1" {
		t.Errorf("keyed on %q; want the client's fingerprint", k.Scheme)
	}
}
