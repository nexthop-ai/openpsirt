// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/attach"
)

func put(t *testing.T, files *attach.Files, key, content string) error {
	t.Helper()
	return files.Put(context.Background(), key, strings.NewReader(content),
		int64(len(content)), "text/plain")
}

func read(t *testing.T, files *attach.Files, key string) string {
	t.Helper()
	body, err := files.Open(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	got, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(got)
}

// A write a crash left behind does not block the next write of that key.
//
// A process killed part way through a write leaves its partial file on disk,
// and the published directory rewrites the same keys every pass.
func TestAWriteLeftBehindDoesNotBlockTheNext(t *testing.T) {
	dir := t.TempDir()
	files, err := attach.NewServedFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.txt.partial"), []byte("half"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := put(t, files, "index.txt", "whole"); err != nil {
		t.Fatalf("a partial file left by an earlier write refused this one: %v", err)
	}
	if got := read(t, files, "index.txt"); got != "whole" {
		t.Fatalf("read back %q", got)
	}
}

// A partial file an interrupted write left is removed once it is old enough
// that no write can still be making it, and a recent one is left alone.
func TestAnAbandonedPartialFileIsRemoved(t *testing.T) {
	dir := t.TempDir()
	files, err := attach.NewServedFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "feed.json.0011223344556677.partial")
	recent := filepath.Join(dir, "feed.json.8899aabbccddeeff.partial")
	other := filepath.Join(dir, "other.json.0011223344556677.partial")
	for _, name := range []string{old, recent, other} {
		if err := os.WriteFile(name, []byte("half"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	long := time.Now().Add(-2 * time.Hour)
	for _, name := range []string{old, other} {
		if err := os.Chtimes(name, long, long); err != nil {
			t.Fatal(err)
		}
	}
	if err := put(t, files, "feed.json", "whole"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("an abandoned partial of the key written is still there: %v", err)
	}
	if _, err := os.Stat(recent); err != nil {
		t.Fatalf("a partial another write may still be making was removed: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("a partial of another key was removed: %v", err)
	}
}

// A store is handed exactly the bytes it is told to expect, or it refuses.
func TestAFileStoreRefusesABodyOfTheWrongLength(t *testing.T) {
	files, err := attach.NewFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := files.Put(ctx, "short", strings.NewReader("abc"), 4, "text/plain"); err == nil {
		t.Fatal("a body shorter than declared was stored")
	}
	if err := files.Put(ctx, "long", strings.NewReader("abcde"), 4, "text/plain"); err == nil {
		t.Fatal("a body longer than declared was stored, cut to the declared length")
	}
	for _, key := range []string{"short", "long"} {
		if _, err := files.Open(ctx, key); err != attach.ErrNoSuchObject {
			t.Fatalf("%s: a refused write left a file: %v", key, err)
		}
	}
}
