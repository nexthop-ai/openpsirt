// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// slowGit stands in for git: a clone writes 20 KB into the directory it names
// over a fraction of a second, and a fetch writes into the copy it runs in for
// as long as it is let.
const slowGit = `#!/bin/sh
for last; do :; done
case " $* " in
*" clone "*)
	mkdir -p "$last"; touch "$last/HEAD"
	i=0
	while [ $i -lt 20 ]; do head -c 1000 /dev/zero >> "$last/pack"; sleep 0.02; i=$((i+1)); done
	;;
*" fetch "*)
	while :; do head -c 1000 /dev/zero >> pack; sleep 0.01; done
	;;
esac
`

func stubGit(t *testing.T) git {
	t.Helper()
	path := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(path, []byte(slowGit), 0o700); err != nil { //nolint:gosec // G306: the stub has to be executable
		t.Fatal(err)
	}
	return git{path: path, transport: "file"}
}

// heldCopy makes a finished copy of bytes size, last used at used.
func heldCopy(t *testing.T, c copies, repository string, bytes int, used time.Time) string {
	t.Helper()
	dir := c.dirFor(repository)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"HEAD": nil, "pack": make([]byte, bytes)} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c.now = func() time.Time { return used }
	c.touch(dir)
	return dir
}

func TestRoomIsMadeWhileANewCopyArrives(t *testing.T) {
	var gone []string
	c := copies{root: t.TempDir(), quota: 25_000, now: time.Now, poll: 5 * time.Millisecond,
		gone: func(names []string) { gone = append(gone, names...) }}
	old := heldCopy(t, c, "https://example.org/old.git", 15_000, time.Now().Add(-time.Hour))

	dir, err := c.ensure(t.Context(), stubGit(t), "https://example.org/new.git")
	if err != nil {
		t.Fatal(err)
	}
	// ensure makes room only while the copy arrives; nothing after it does.
	// The old copy gone means it went while the new one was being written.
	if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
		t.Error("the old copy is still there, so nothing made room while the new one arrived")
	}
	if !slices.Equal(gone, []string{filepath.Base(old)}) {
		t.Errorf("reported %v as removed, want the old copy", gone)
	}
	if _, err := os.Stat(filepath.Join(dir, "HEAD")); err != nil {
		t.Errorf("the new copy is not in place: %v", err)
	}
}

func TestAFetchThatOutgrowsTheCacheIsStoppedAndItsCopyRemoved(t *testing.T) {
	var gone []string
	c := copies{root: t.TempDir(), quota: 10_000, now: time.Now, poll: 5 * time.Millisecond,
		gone: func(names []string) { gone = append(gone, names...) }}
	repository := "https://example.org/endless.git"
	dir := heldCopy(t, c, repository, 1_000, time.Now())

	// The stub fetch never ends on its own. Only the watcher stops it inside
	// this deadline.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, err := c.ensure(ctx, stubGit(t), repository)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("an endless fetch ended with %v, want it stopped as too large", err)
	}
	if ctx.Err() != nil {
		t.Fatal("the fetch ran until the test's own deadline")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Error("a copy that outgrew the cache was kept")
	}
	if !slices.Equal(gone, []string{filepath.Base(dir)}) {
		t.Errorf("reported %v as removed, want the copy that outgrew the cache", gone)
	}
}

func TestEveryBranchIsCountedAndAHundredAreKept(t *testing.T) {
	var lines branchLines
	// Written in pieces that split lines, the way a pipe delivers them.
	var all []byte
	for i := 20_000; i > 0; i-- {
		all = append(all, []byte("release-"+strconv.Itoa(i)+"\n")...)
	}
	all = append(all, []byte(strings.Repeat("x", 10_000)+"\n")...)
	all = append(all, []byte("last-without-a-newline")...)
	for len(all) > 0 {
		n := min(777, len(all))
		if _, err := lines.Write(all[:n]); err != nil {
			t.Fatal(err)
		}
		all = all[n:]
	}
	lines.end()
	kept := lines.kept()
	if lines.count != 20_002 {
		t.Errorf("counted %d branches, want 20002", lines.count)
	}
	if len(kept) != MostBranches || kept[0] != "last-without-a-newline" || kept[1] != "release-1" ||
		kept[MostBranches-1] != "release-99" {
		t.Errorf("kept %d, from %q to %q; want the first %d in version order",
			len(kept), kept[0], kept[len(kept)-1], MostBranches)
	}
	// What one line may hold, whatever the line was: append rounds capacity
	// up, so the bound is twice the longest kept rather than the longest.
	if cap(lines.line) > 2*longestLine {
		t.Errorf("held %d bytes for one line, want at most %d", cap(lines.line), 2*longestLine)
	}
}
