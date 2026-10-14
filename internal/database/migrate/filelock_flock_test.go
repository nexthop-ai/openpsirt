// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package migrate

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A process waiting for another's migration stops waiting when it is told to
// stop, whether it is told before it first asks or while it waits. A shutdown
// that waited out the whole bound would hold a replacement for five minutes
// after it was asked to go.
func TestAWaitForTheFileLockEndsWhenItsContextDoes(t *testing.T) {
	path := t.TempDir() + "/locked.db" + lockSuffix
	release, err := lockFile(t.Context(), path, time.Minute)
	if err != nil {
		t.Fatalf("the first holder could not take the lock: %v", err)
	}
	defer func() { _ = release(context.Background()) }()

	t.Run("already ended", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		start := time.Now()
		if _, err := lockFile(ctx, path, time.Minute); !errors.Is(err, context.Canceled) {
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
		if _, err := lockFile(ctx, path, time.Minute); !errors.Is(err, context.DeadlineExceeded) {
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
	_, err := lockFile(t.Context(), t.TempDir()+"/broken.db"+lockSuffix, time.Minute)
	if err == nil || !errors.Is(err, syscall.EIO) || !strings.Contains(err.Error(), "take the migration lock") {
		t.Errorf("a failing lock answered %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("a failure was waited on for %v", elapsed)
	}
}
