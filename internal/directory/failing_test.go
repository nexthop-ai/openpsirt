// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package directory_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/directory"
)

// errStore is what a store failing a write answers.
var errStore = errors.New("the store did not take the file")

// failing is a store that refuses every write whose key the test names.
type failing struct {
	attach.Storage
	mu    sync.Mutex
	fails func(key string) bool
}

func (s *failing) Put(ctx context.Context, key string, body io.Reader, size int64, contentType string) error {
	s.mu.Lock()
	fails := s.fails
	s.mu.Unlock()
	if fails != nil && fails(key) {
		return errStore
	}
	return s.Storage.Put(ctx, key, body, size, contentType)
}

// failWhere sets which keys the store refuses; nil refuses none.
func (s *failing) failWhere(fails func(key string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fails = fails
}

// failingWriter is a writer over the fixture's store that refuses the writes
// the test names.
func (f *fixture) failingWriter(t *testing.T) (*directory.Writer, *failing) {
	t.Helper()
	store := &failing{Storage: f.files}
	writer := directory.New(f.db, directory.Published(store), issuer,
		directory.Config{List: true, Mirror: false}, "test", f.logger)
	if writer == nil {
		t.Fatal("no writer was started")
	}
	return writer, store
}

// held reports whether the directory holds a file.
func (f *fixture) held(t *testing.T, at string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(f.where, filepath.FromSlash(at)))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// A document the store does not take fails the pass before any list names it,
// and the next pass writes everything, rather than finding the set it meant to
// write already written.
func TestADocumentTheStoreRefusesIsWrittenAgainAndNeverListedFirst(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.issued(t, "A flaw in the recovery console")
		writer, store := f.failingWriter(t)
		store.failWhere(func(key string) bool { return strings.Contains(key, "/") })
		if _, err := writer.Write(t.Context()); !errors.Is(err, errStore) {
			t.Fatalf("a pass whose document the store refused answered %v", err)
		}
		if f.held(t, "index.txt") {
			t.Error("the list of documents was written though a document it names was not")
		}

		store.failWhere(nil)
		written, err := writer.Write(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if written.Unchanged || written.Documents != 1 || !f.held(t, "index.txt") {
			t.Errorf("the pass after a refused write wrote %+v, want every file written", written)
		}
	})
}

// Each list the store does not take fails the pass, naming it, and the next
// pass writes it.
func TestAListTheStoreRefusesIsWrittenAgain(t *testing.T) {
	for _, list := range []string{"index.txt", "changes.csv", "feed-tlp-white.json", "provider-metadata.json"} {
		t.Run(list, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.issued(t, "A flaw in the recovery console")
				writer, store := f.failingWriter(t)
				store.failWhere(func(key string) bool { return key == list })
				_, err := writer.Write(t.Context())
				if !errors.Is(err, errStore) || !strings.Contains(err.Error(), "write "+list) {
					t.Fatalf("a pass whose %s the store refused answered %v", list, err)
				}
				if f.held(t, list) {
					t.Fatalf("%s is held though the store refused it", list)
				}

				store.failWhere(nil)
				written, err := writer.Write(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if written.Unchanged || !f.held(t, list) {
					t.Errorf("the pass after %s was refused wrote %+v, and holds it: %v",
						list, written, f.held(t, list))
				}
			})
		})
	}
}
