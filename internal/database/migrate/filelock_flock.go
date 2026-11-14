// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package migrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// flock is the system call that takes the lock, a variable so a test can make it
// fail the way a broken file system does.
var flock = syscall.Flock

// lockFile takes an exclusive advisory lock on path, waiting for as long as
// another process holds it.
//
// Tried rather than blocked on, in a loop: a blocking flock cannot be
// interrupted by a shutdown, and says nothing while it waits. Between tries
// the wait looks at its context, and about once every waitLogEvery it names the
// holder the file records.
//
// The kernel drops the lock when the process ends, so there is no state here to
// go stale. The file is left behind deliberately — removing it would race with
// the next process opening it, and a small file beside the database costs
// nothing. What it records is read only while somebody holds the lock, and the
// holder rewrites it as it takes the lock.
func lockFile(ctx context.Context, path string, logger *slog.Logger) (unlock, error) {
	path = filepath.Clean(path)
	// Never through a link, symbolic or hard, and only a regular file: the
	// holder truncates it and writes into it, so a link planted beside the
	// database would have that written into whatever it points at.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the migration lock beside the database: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("read the migration lock beside the database: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("the migration lock beside the database is not a regular file: %s", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("the migration lock beside the database has another name: %s", path)
	}

	waits := waiting{logger: logger, since: time.Now()}
	for {
		err := flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			recordHolder(file)
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
		waits.still(func() string { return heldBy(file) })
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// heldByMost is the most of the lock file a waiter reads: more than a
// holder writes.
const heldByMost = 512

// recordHolder writes which process holds the lock into the lock file.
//
// A failure leaves the file naming an earlier holder or nobody, which costs a
// waiter the name and nothing else, so it is not an error.
func recordHolder(file *os.File) {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "an unnamed host"
	}
	if err := file.Truncate(0); err != nil {
		return
	}
	_, _ = file.WriteAt([]byte(fmt.Sprintf("process %d on %s\n", os.Getpid(), host)), 0)
}

// heldBy reads which process the lock file says holds it, in the form the
// server engines' holder takes, or nothing where the file records nobody.
// Read through the descriptor that was checked, never the path again, which
// could name something else by now.
func heldBy(file *os.File) string {
	recorded := make([]byte, heldByMost)
	n, err := file.ReadAt(recorded, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return ""
	}
	if held := strings.TrimSpace(string(recorded[:n])); held != "" {
		return " by " + held
	}
	return ""
}
