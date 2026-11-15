// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A connection holding the migration lock is closed, never pooled, when its
// release fails: a keep-alive use stalled past the release's bound, or an
// unlock statement that failed. Its session still holds the lock, and a
// pooled connection carries it to whichever query takes it next, so every
// other replica's start waits out the connection's lifetime.
//
// Driven through the migration's own lock and release over a scripted driver,
// so the release's bound, the abandoning and the closing are the ones a
// migration runs.
func TestALockConnectionWhoseReleaseFailsIsClosedNotPooled(t *testing.T) {
	restoreKeep, restoreReset := keepAliveEvery, resetWait
	keepAliveEvery, resetWait = 10*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { keepAliveEvery, resetWait = restoreKeep, restoreReset })

	for _, engine := range []database.Engine{database.Postgres, database.MySQL} {
		for _, each := range []struct {
			name                       string
			stallKeepAlive, failUnlock bool
		}{
			{"a keep-alive use stalls", true, false},
			{"the unlock fails", false, true},
		} {
			t.Run(string(engine)+"/"+each.name, func(t *testing.T) {
				script := &lockScript{
					stallKeepAlive: each.stallKeepAlive, failUnlock: each.failUnlock,
					started: make(chan struct{}), unstall: make(chan struct{}),
				}
				pool := sql.OpenDB(script)
				defer func() { _ = pool.Close() }()
				query, err := database.Query(pool, engine)
				if err != nil {
					t.Fatal(err)
				}
				db := &database.DB{DB: query, Server: database.Server{Engine: engine}}
				logger := slog.New(slog.NewTextHandler(io.Discard, nil))

				returned := make(chan error, 1)
				go func() {
					returned <- withLock(t.Context(), db, logger, func(context.Context, *held) error {
						if script.stallKeepAlive {
							<-script.started
						}
						return nil
					})
				}()
				select {
				case err := <-returned:
					if err == nil {
						t.Error("a release that failed answered that the lock was released")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("the migration did not return, so its release was not bounded")
				}
				close(script.unstall)

				deadline := time.Now().Add(5 * time.Second)
				for script.closed.Load() == 0 && time.Now().Before(deadline) {
					time.Sleep(10 * time.Millisecond)
				}
				if script.closed.Load() == 0 {
					t.Error("the connection holding the lock was never closed")
				}
				if open := pool.Stats().OpenConnections; open != 0 {
					t.Errorf("the pool holds %d connections after the lock's release failed", open)
				}
			})
		}
	}
}

// lockScript is a driver, and its own connector, answering the statements the
// migration lock makes: every lock is granted, a keep-alive use may stall
// until unstalled, and an unlock may fail the way a statement whose context
// has ended does.
type lockScript struct {
	stallKeepAlive bool
	failUnlock     bool

	once    sync.Once
	started chan struct{}
	unstall chan struct{}
	closed  atomic.Int32
}

func (s *lockScript) Open(string) (driver.Conn, error)             { return lockConn{s}, nil }
func (s *lockScript) Connect(context.Context) (driver.Conn, error) { return lockConn{s}, nil }
func (s *lockScript) Driver() driver.Driver                        { return s }

type lockConn struct{ s *lockScript }

func (c lockConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c lockConn) Close() error                        { c.s.closed.Add(1); return nil }
func (c lockConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func (c lockConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if query == "SELECT 1" && c.s.stallKeepAlive {
		c.s.once.Do(func() { close(c.s.started) })
		<-c.s.unstall
	}
	return driver.RowsAffected(0), nil
}

func (c lockConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "DATABASE()"):
		return &oneRow{value: "openpsirt"}, nil
	case strings.Contains(query, "unlock") || strings.Contains(query, "RELEASE_LOCK"):
		if c.s.failUnlock {
			return nil, context.DeadlineExceeded
		}
		return &oneRow{value: int64(1)}, nil
	case strings.Contains(query, "GET_LOCK"):
		return &oneRow{value: int64(1)}, nil
	}
	return nil, errors.New("the script has no answer for " + query)
}

// oneRow is a result of one row of one column.
type oneRow struct {
	value driver.Value
	done  bool
}

func (r *oneRow) Columns() []string { return []string{"answer"} }
func (r *oneRow) Close() error      { return nil }
func (r *oneRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.value
	return nil
}
