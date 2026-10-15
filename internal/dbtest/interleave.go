// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// The seams a test uses to put another writer, or a failure, at one point in
// what the code under test does. One copy of each, because copies drift on
// exactly the question that matters: when the rival fires, and whether the
// schema is put back.
//
// A statement is recognized by its first word and by a table it names in
// quotes, either of the two quoting styles the engines use.

// names reports whether a statement names table, quoted.
func names(query, table string) bool {
	return strings.Contains(query, `"`+table+`"`) || strings.Contains(query, "`"+table+"`")
}

// verbOf is a statement's first word, in capitals.
func verbOf(query string) string {
	word, _, _ := strings.Cut(strings.TrimSpace(query), " ")
	return strings.ToUpper(word)
}

// writes reports whether a verb changes rows.
func writes(verb string) bool {
	return verb == "INSERT" || verb == "UPDATE" || verb == "DELETE"
}

// RivalAfterRead returns a handle over db's connections on which a rival
// writer lands between a read of one table and the next write to another, and
// a function that waits for the rival and answers what it returned. The two
// are one table for a conditional write to a row that was read.
//
// The handle arms once a statement reading the first table has run, and the
// first statement after it that writes the second starts rival on another
// goroutine and
// waits up to wait for it to finish before it goes on. That is the
// interleaving a conditional write or a lost-race retry exists for: the
// transaction has read the row and is about to write it, and somebody else's
// write lands in between. A rival that has to wait on a lock the transaction
// holds does not finish in that time, and lands once the transaction commits.
//
// The rival runs on db, never on the returned handle, so its own statements
// do not fire the seam. A test whose rival never ran fails, because nothing
// landed between the read and the write. SQLite has one connection and one
// writer, so the interleaving cannot happen there and the test is skipped.
func RivalAfterRead(t *testing.T, db *database.DB, read, write string, wait time.Duration,
	rival func() error) (*bun.DB, func() error) {

	t.Helper()
	if db.Stats().MaxOpenConnections == 1 {
		t.Skip("one connection: nothing lands between a read and a write")
	}
	hook := &afterRead{read: read, write: write, wait: wait, rival: rival, done: make(chan error, 1)}
	hooked := bun.NewDB(db.DB.DB, db.Dialect()).WithQueryHook(hook)
	var answer error
	var waited sync.Once
	finished := func() error {
		waited.Do(func() {
			if !hook.started() {
				t.Error("the rival never ran, so nothing landed between the read and the write")
				return
			}
			answer = <-hook.done
		})
		return answer
	}
	t.Cleanup(func() { _ = finished() })
	return hooked, finished
}

type afterRead struct {
	read  string
	write string
	wait  time.Duration
	rival func() error
	done  chan error

	mu    sync.Mutex
	armed bool
	fired bool
}

func (h *afterRead) started() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fired
}

func (h *afterRead) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	verb := verbOf(e.Query)
	h.mu.Lock()
	if verb == "SELECT" && names(e.Query, h.read) {
		h.armed = true
	}
	fire := h.armed && !h.fired && writes(verb) && names(e.Query, h.write)
	if fire {
		h.fired = true
	}
	h.mu.Unlock()
	if !fire {
		return ctx
	}
	landed := make(chan error, 1)
	go func() { landed <- h.rival() }()
	select {
	case err := <-landed:
		h.done <- err
	case <-time.After(h.wait):
		go func() { h.done <- <-landed }()
	}
	return ctx
}

func (h *afterRead) AfterQuery(context.Context, *bun.QueryEvent) {}

// Hooked is db with hook watching every statement made through it, and
// nothing made through db itself or through any other handle over the same
// connections. A store under test is built on the handle this returns, which
// is how the hook reaches what the store does.
func Hooked(db *database.DB, hook bun.QueryHook) *database.DB {
	hooked := *db
	hooked.DB = db.WithQueryHook(hook)
	return &hooked
}

// Fault makes one statement on a handle fail, by handing the driver a context
// that has already ended. The failure carries context.Canceled, which is how a
// test tells it from any other. It is a query hook, added to the handle whose
// statement is to fail.
type Fault struct {
	mu    sync.Mutex
	verb  string
	table string
	fired bool
}

// Arm makes the next statement starting with verb and naming table fail.
func (f *Fault) Arm(verb, table string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verb, f.table, f.fired = strings.ToUpper(verb), table, false
}

// Disarm stops the fault and reports whether it made a statement fail.
func (f *Fault) Disarm() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	fired := f.fired
	f.verb, f.table, f.fired = "", "", false
	return fired
}

func (f *Fault) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.verb == "" || f.fired || verbOf(e.Query) != f.verb || !names(e.Query, f.table) {
		return ctx
	}
	f.fired = true
	failed, cancel := context.WithCancel(ctx)
	cancel()
	return failed
}

func (f *Fault) AfterQuery(context.Context, *bun.QueryEvent) {}

// Hide takes table out of the schema by renaming it, and returns a function
// that puts it back. It is put back when the test ends if the test has not
// done so, through a failure or a fatal included: a server database is
// shared by every test of a package, and a schema left with a hole in it
// fails every later one in a way that reads as an engine disagreement.
func Hide(t *testing.T, db bun.IDB, table string) (restore func()) {
	t.Helper()
	ctx := t.Context()
	away := table + "_hidden"
	if _, err := db.ExecContext(ctx, `ALTER TABLE "`+table+`" RENAME TO "`+away+`"`); err != nil {
		t.Fatalf("take %s away: %v", table, err)
	}
	var once sync.Once
	restore = func() {
		once.Do(func() {
			if _, err := db.ExecContext(context.WithoutCancel(ctx),
				`ALTER TABLE "`+away+`" RENAME TO "`+table+`"`); err != nil {
				t.Errorf("%s was not put back, so every later test reads a schema with a hole in it: %v",
					table, err)
			}
		})
	}
	t.Cleanup(restore)
	return restore
}

// Closed is a database every call to fails: one that was opened and closed.
//
// Opened first, because a process with no database answers every request
// from the router, which is a different arm.
func Closed(t *testing.T) *database.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gone.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := database.ParseURL("sqlite://" + path)
	if err != nil {
		t.Fatal(err)
	}
	gone, err := database.Open(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if err := gone.Close(); err != nil {
		t.Fatal(err)
	}
	return gone
}
