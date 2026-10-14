// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"strings"
	"testing"
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
	return dir
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
