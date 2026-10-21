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
