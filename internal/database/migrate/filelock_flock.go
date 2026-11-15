// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package migrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	file, err := openLockFile(path, "migration lock", 0o600)
	if err != nil {
		return nil, err
	}

	waits := waiting{logger: logger, since: time.Now()}
	for {
		err := flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			recordHolder(file)
			return releaseFile(file, "migration lock"), nil
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

// openLockFile opens a lock file beside the database for writing, creating it
// where it is absent.
//
// Never through a link, symbolic or hard, and only a regular file: the holder
// truncates it and writes into it, so a link planted beside the database would
// have that written into whatever it points at.
func openLockFile(path, what string, mode os.FileMode) (*os.File, error) {
	path = filepath.Clean(path)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return nil, fmt.Errorf("open the %s beside the database: %w", what, err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("read the %s beside the database: %w", what, err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("the %s beside the database is not a regular file: %s", what, path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || st.Nlink != 1 {
		_ = file.Close()
		return nil, fmt.Errorf("the %s beside the database has another name: %s", what, path)
	}
	return file, nil
}

// releaseFile lets a lock taken on file go.
func releaseFile(file *os.File, what string) unlock {
	return func(context.Context) error {
		// Closing the descriptor releases the lock; doing both says so.
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
			_ = file.Close()
			return fmt.Errorf("release the %s: %w", what, err)
		}
		return file.Close()
	}
}

// changeMode is the schema change lock file's mode: readable by every user.
const changeMode os.FileMode = 0o644

// readableByAll gives the schema change lock file changeMode where it lacks
// it.
func readableByAll(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("read the schema change lock beside the database: %w", err)
	}
	if info.Mode().Perm() == changeMode {
		return nil
	}
	if err := file.Chmod(changeMode); err != nil {
		return fmt.Errorf("make the schema change lock beside the database readable by every user: %w", err)
	}
	return nil
}

// changeEvery is how long taking the schema change lock waits between tries.
const changeEvery = 10 * time.Millisecond

// changeFile takes the schema change lock on the file at path, beside the
// migration lock already held.
//
// A serving instance asking whether the schema is changing holds a shared
// lock for the moment it asks, so the tries say nothing for the length of one
// attempt at the migration lock. Past it the holder is something else, and
// the wait is logged about once every waitLogEvery.
//
// The file holds nothing, and any process that may serve the database reads
// it, whichever user applies the migrations. Its mode is set after opening,
// since the process's umask narrows the mode a file is created with.
func changeFile(ctx context.Context, path string, logger *slog.Logger) (unlock, error) {
	file, err := openLockFile(path, "schema change lock", changeMode)
	if err != nil {
		return nil, err
	}
	if err := readableByAll(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	since := time.Now()
	waits := waiting{logger: logger, since: since, change: true}
	for {
		err := flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return releaseFile(file, "schema change lock"), nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = file.Close()
			return nil, fmt.Errorf("take the schema change lock: %w", err)
		}
		if time.Since(since) >= time.Duration(lockAttemptSeconds)*time.Second {
			waits.still(func() string { return "" })
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(changeEvery):
		}
	}
}

// fileLocked reports whether another process holds an exclusive lock on the
// file at path. An absent file is one nobody has locked.
//
// It takes a shared lock for the moment it asks, and opens the file only to
// read, never through a link, without waiting on a file that is not a
// regular one.
func fileLocked(path string) (bool, error) {
	file, err := os.OpenFile(filepath.Clean(path), //nolint:gosec // G703: the file beside the database the connection named
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("open the schema change lock beside the database: %w", err)
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("read the schema change lock beside the database: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("the schema change lock beside the database is not a regular file: %s", path)
	}
	switch err := syscall.Flock(int(file.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); {
	case errors.Is(err, syscall.EWOULDBLOCK):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("ask the schema change lock beside the database: %w", err)
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	return false, nil
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
