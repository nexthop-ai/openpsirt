// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package migrate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// lockFile takes an exclusive advisory lock on path, waiting up to wait.
//
// Tried rather than blocked on, in a loop, for the same reason the other two
// engines bound their wait: an instance wedged mid-migration must not block
// every replacement silently, because the startup probe then kills each one in
// turn and nothing says why. A blocking flock has no timeout of its own.
//
// The kernel drops the lock when the process ends, so there is no state here to
// go stale. The file is left behind deliberately — removing it would race with
// the next process opening it, and an empty file beside the database costs
// nothing.
func lockFile(ctx context.Context, path string, wait time.Duration) (unlock, error) {
	file, err := os.OpenFile(filepath.Clean(path), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the migration lock beside the database: %w", err)
	}

	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func(context.Context) error {
				// Closing the descriptor releases the lock; doing both says so.
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
					_ = file.Close()
					return fmt.Errorf("release the migration lock: %w", err)
				}
				return file.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = file.Close()
			return nil, fmt.Errorf("take the migration lock: %w", err)
		}
		if ctx.Err() != nil {
			_ = file.Close()
			return nil, ctx.Err()
		}
		if time.Now().After(deadline) {
			_ = file.Close()
			return nil, fmt.Errorf("another process holds the migration lock on this database file")
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
