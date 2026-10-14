// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A git that is stopped is asked to stop, so it removes the lock it holds.
// Killed, it leaves the lock, and every later write of that kind into the
// copy is refused.
func TestAGitThatIsStoppedIsAskedToStopAndClearsItsLock(t *testing.T) {
	const holding = `#!/bin/sh
trap 'rm -f held.lock; exit 1' TERM
touch held.lock
while :; do sleep 0.01; done
`
	program := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(program, []byte(holding), 0o700); err != nil { //nolint:gosec // G306: the stub has to be executable
		t.Fatal(err)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		// Once the lock is taken, the visit is stopped.
		for {
			if _, err := os.Stat(filepath.Join(dir, "held.lock")); err == nil {
				cancel()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	err := git{path: program, transport: "file"}.run(ctx, time.Minute, dir, "", nil, nil,
		"commit-graph", "write")
	if err == nil {
		t.Fatal("a git that was stopped reported success")
	}
	if _, err := os.Stat(filepath.Join(dir, "held.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Error("the lock a stopped git held is still there, so it was killed rather than asked")
	}
}

// A lock a stopped git left in a copy is cleared before the next visit writes
// into it, so a killed visit does not fail every visit after it.
func TestALockAStoppedGitLeftDoesNotFailTheNextVisit(t *testing.T) {
	const refusing = `#!/bin/sh
for lock in objects/info/commit-graph.lock packed-refs.lock refs/heads/main.lock; do
	if [ -e "$lock" ]; then echo "fatal: Unable to create '$lock': File exists." >&2; exit 128; fi
done
`
	program := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(program, []byte(refusing), 0o700); err != nil { //nolint:gosec // G306: the stub has to be executable
		t.Fatal(err)
	}
	c := copies{root: t.TempDir(), quota: DefaultQuota, now: time.Now, poll: 5 * time.Millisecond}
	repository := "https://example.org/locked.git"
	dir := heldCopy(t, c, repository, 1_000, time.Now())
	for _, lock := range []string{"objects/info/commit-graph.lock", "packed-refs.lock",
		"refs/heads/main.lock"} {
		at := filepath.Join(dir, lock)
		if err := os.MkdirAll(filepath.Dir(at), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(at, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.ensure(t.Context(), git{path: program, transport: "file"}, repository); err != nil {
		t.Errorf("a copy a stopped git left locked failed the next visit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		t.Errorf("clearing the locks took more than the locks: %v", err)
	}
}
