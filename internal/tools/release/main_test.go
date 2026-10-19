// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate/released"
)

// repository makes a git repository with one commit, tagged with each of tags.
func repository(t *testing.T, tags ...string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...) //nolint:gosec // G204: arguments this test writes
		cmd.Dir = dir
		cmd.Env = append(cmd.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("commit", "-q", "--allow-empty", "-m", "root")
	for _, tag := range tags {
		run("tag", tag)
	}
	for _, sub := range []string{root, migrations} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// record writes a frozen release's record into the checkout at dir, owning the
// checkout's one migration.
func record(t *testing.T, dir, version string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, migrations, "00001_first.go"), []byte("package migrations\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := filepath.Join(dir, root, version)
	if err := os.MkdirAll(at, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(at, released.Files), []byte("last 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestATaggedReleaseIsNotFrozenAgain(t *testing.T) {
	dir := repository(t, "v0.7.0")
	for _, tag := range []string{"v0.7.0", "v0.7.0-rc.2"} {
		if err := guard(dir, tag); err == nil || !strings.Contains(err.Error(), "is tagged") {
			t.Errorf("freezing %s, whose release is tagged, answered %v", tag, err)
		}
	}
	if err := guard(dir, "v0.8.0"); err != nil {
		t.Errorf("freezing an untagged release was refused: %v", err)
	}
}

// A checkout without tags still refuses a release freezing would refuse, so the
// schema records it holds are not rewritten before the refusal.
func TestAReleaseFreezingWouldRefuseIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	dir := repository(t)
	record(t, dir, "v0.8.0")
	for _, c := range []struct{ tag, says string }{
		{"v0.7.0", "older than v0.8.0"},
	} {
		if err := guard(dir, c.tag); err == nil || !strings.Contains(err.Error(), c.says) {
			t.Errorf("guarding %s answered %v, want %q", c.tag, err, c.says)
		}
	}
	for _, tag := range []string{"v0.9.0", "v0.10.0"} {
		if err := guard(dir, tag); err != nil {
			t.Errorf("guarding %s, a newer release, was refused: %v", tag, err)
		}
	}
}

func TestACheckoutGitCannotReadRefusesToFreeze(t *testing.T) {
	// Not a repository: git exits 128, which is not the answer "no such tag".
	if err := guard(t.TempDir(), "v0.8.0"); err == nil || !strings.Contains(err.Error(), "could not say") {
		t.Errorf("freezing outside a repository answered %v, want a refusal", err)
	}
}

func TestATagThatIsNotAReleaseIsRefused(t *testing.T) {
	if err := guard(repository(t), "nightly"); err == nil {
		t.Error("freezing a tag that is not a release was not refused")
	}
}
