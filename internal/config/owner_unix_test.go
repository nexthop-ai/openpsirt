// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A pipe with nothing writing to it is refused at once. Opened first, it
// would hold the start until something wrote to it.
func TestAConfigurationPipeIsRefusedWithoutWaiting(t *testing.T) {
	pipe := filepath.Join(t.TempDir(), "openpsirt.toml")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	answered := make(chan error, 1)
	go func() {
		_, err := LoadFile(pipe, nil)
		answered <- err
	}()
	select {
	case err := <-answered:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("a pipe answered %v, want it refused as not a regular file", err)
		}
	case <-time.After(5 * time.Second):
		// Unblocks the open, so the goroutine ends with the test.
		if w, err := os.OpenFile(pipe, os.O_WRONLY, 0); err == nil { //nolint:gosec // G304: the pipe this test made
			_ = w.Close()
		}
		t.Fatal("a pipe with no writer held the start")
	}
}

// LoadFile refuses a file its process's user does not own, read through the
// same path a start takes rather than through the rule alone.
func TestAConfigurationFileIsRefusedWhenAnotherUserOwnsIt(t *testing.T) {
	me := os.Geteuid()
	if me == 0 {
		t.Skip("a file root owns is accepted for every user, so running as root cannot show the refusal")
	}
	path := writeFile(t, "")
	geteuid = func() int { return me + 1 }
	t.Cleanup(func() { geteuid = os.Geteuid })
	if _, err := LoadFile(path, nil); err == nil || !strings.Contains(err.Error(), "owned by user") {
		t.Errorf("a file another user owns answered %v, want it refused for its owner", err)
	}
}
