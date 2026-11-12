// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package migrate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A process waiting for another's migration stops waiting when it is told to
// stop, whether it is told before it first asks or while it waits. The wait
// has no bound of its own, so being told to stop is the only thing that ends
// it while the lock is held.
func TestAWaitForTheFileLockEndsWhenItsContextDoes(t *testing.T) {
	path := t.TempDir() + "/locked.db" + lockSuffix
	release, err := lockFile(t.Context(), path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the first holder could not take the lock: %v", err)
	}
	defer func() { _ = release(context.Background()) }()

	t.Run("already ended", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		start := time.Now()
		if _, err := lockFile(ctx, path, slog.New(slog.DiscardHandler)); !errors.Is(err, context.Canceled) {
			t.Errorf("an ended context answered %v", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("it waited %v after its context ended", elapsed)
		}
	})
	t.Run("ending while it waits", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, err := lockFile(ctx, path, slog.New(slog.DiscardHandler)); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("a context ending part way answered %v", err)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("it waited %v after its context ended", elapsed)
		}
	})
}

// A failure that is not somebody else holding the lock is reported at once,
// rather than waited on as though it were.
func TestAFileLockThatCannotBeTakenIsNotWaitedOn(t *testing.T) {
	restore := flock
	flock = func(int, int) error { return syscall.EIO }
	t.Cleanup(func() { flock = restore })

	start := time.Now()
	_, err := lockFile(t.Context(), t.TempDir()+"/broken.db"+lockSuffix, slog.New(slog.DiscardHandler))
	if err == nil || !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "take the migration lock") {
		t.Errorf("a failing lock answered %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("a failure was waited on for %v", elapsed)
	}
}

// A process waiting on another's migration of one SQLite file waits for as
// long as the other holds the lock, naming it each time it says so, and takes
// the lock once it is let go.
func TestAWaiterTakesTheFileLockWhenItsHolderLetsGo(t *testing.T) {
	restore := waitLogEvery
	waitLogEvery = 100 * time.Millisecond
	t.Cleanup(func() { waitLogEvery = restore })

	path := t.TempDir() + "/locked.db" + lockSuffix
	release, err := lockFile(t.Context(), path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the first holder could not take the lock: %v", err)
	}

	said := &lines{}
	taken := make(chan error, 1)
	go func() {
		again, err := lockFile(t.Context(), path, said.logger())
		if err == nil {
			err = again(context.Background())
		}
		taken <- err
	}()
	select {
	case err := <-taken:
		t.Fatalf("the waiter stopped waiting while the lock was held: %v", err)
	case <-time.After(time.Second):
	}
	holder := fmt.Sprintf("process %d on ", os.Getpid())
	if got := strings.Count(said.String(), holder); got < 2 {
		t.Errorf("a wait of a second named the holder %d times: %q", got, said.String())
	}

	if err := release(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-taken:
		if err != nil {
			t.Errorf("the waiter answered %v once the lock was let go", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter did not take the lock within 5s of its release")
	}
}

// A waiter names the holder from the file it opened and checked, never from
// whatever its path names by the time it asks.
func TestAWaiterReadsTheHolderFromTheFileItChecked(t *testing.T) {
	restore := waitLogEvery
	waitLogEvery = 50 * time.Millisecond
	t.Cleanup(func() { waitLogEvery = restore })

	dir := t.TempDir()
	path := dir + "/locked.db" + lockSuffix
	release, err := lockFile(t.Context(), path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the first holder could not take the lock: %v", err)
	}
	defer func() { _ = release(context.Background()) }()

	said := &lines{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_, _ = lockFile(ctx, path, said.logger())
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(said.String(), "process ") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	const secret = "something the service user keeps"
	victim := dir + "/kept"
	if err := os.WriteFile(victim, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	before := len(said.String())
	for len(said.String()) == before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-stopped
	if strings.Contains(said.String(), secret) {
		t.Errorf("the waiter named the holder from what its path pointed at:\n%s", said.String())
	}
	if len(said.String()) == before {
		t.Error("the waiter said nothing after the path was swapped, so this checked nothing")
	}
}

// The lock file is never opened through a link or as anything but a regular
// file. The holder truncates it and writes into it, so a link planted beside
// the database would clobber the file it points at.
func TestTheFileLockIsNeverTakenThroughALink(t *testing.T) {
	dir := t.TempDir()
	victim := dir + "/kept"
	const kept = "something the service user keeps\n"
	if err := os.WriteFile(victim, []byte(kept), 0o600); err != nil {
		t.Fatal(err)
	}
	path := dir + "/linked.db" + lockSuffix
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if release, err := lockFile(t.Context(), path, slog.New(slog.DiscardHandler)); err == nil {
		_ = release(context.Background())
		t.Error("the migration lock was taken through a link")
	}
	if got, err := os.ReadFile(filepath.Clean(victim)); err != nil || string(got) != kept {
		t.Errorf("the file the link points at now holds %q (%v)", got, err)
	}

	hard := dir + "/hard.db" + lockSuffix
	if err := os.Link(victim, hard); err != nil {
		t.Fatal(err)
	}
	if release, err := lockFile(t.Context(), hard, slog.New(slog.DiscardHandler)); err == nil {
		_ = release(context.Background())
		t.Error("the migration lock was taken through a hard link")
	}
	if got, err := os.ReadFile(filepath.Clean(victim)); err != nil || string(got) != kept {
		t.Errorf("the file the hard link names now holds %q (%v)", got, err)
	}

	pipe := dir + "/pipe.db" + lockSuffix
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	if release, err := lockFile(t.Context(), pipe, slog.New(slog.DiscardHandler)); err == nil {
		_ = release(context.Background())
		t.Error("the migration lock was taken on a named pipe")
	}
}
