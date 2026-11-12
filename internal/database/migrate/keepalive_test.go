// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The keep-alive's use of the lock's connection carries no deadline and
// outlives the migration's context. Both drivers close a connection whose
// query outlived its context, and closing the connection releases the lock, so
// a use that can time out is one a network stall turns into a lost lock.
func TestTheKeepAliveUseHasNoDeadline(t *testing.T) {
	recorded := &contextRecorder{}
	// Opened from a connector rather than registered by name, because the
	// driver registry is global and a second run in one process would
	// register the name twice.
	db := sql.OpenDB(recorded)
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	restore := keepAliveEvery
	keepAliveEvery = 10 * time.Millisecond
	t.Cleanup(func() { keepAliveEvery = restore })

	ctx, cancel := context.WithTimeout(t.Context(), time.Hour)
	keeping := keepAlive(ctx, conn)
	deadline := time.Now().Add(5 * time.Second)
	for recorded.uses() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := keeping.stop(context.Background()); err != nil {
		t.Fatal(err)
	}

	if recorded.uses() == 0 {
		t.Fatal("the keep-alive never used the connection")
	}
	if recorded.deadlined {
		t.Error("a keep-alive use carried a deadline, which closes the connection holding the lock")
	}
}

// Stopping the keep-alive waits for its last use only as long as the release
// may take. A use a stalled connection holds is said, never waited on: it
// lasts until the operating system gives up on the connection.
func TestStoppingTheKeepAliveDoesNotWaitOnAStalledUse(t *testing.T) {
	stalled := &stallingConnector{started: make(chan struct{}), unstall: make(chan struct{})}
	db := sql.OpenDB(stalled)
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	restore := keepAliveEvery
	keepAliveEvery = 10 * time.Millisecond
	t.Cleanup(func() { keepAliveEvery = restore })

	keeping := keepAlive(t.Context(), conn)
	<-stalled.started
	bounded, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	began := time.Now()
	err = keeping.stop(bounded)
	if err == nil {
		t.Error("stopping a keep-alive whose use is stalled answered that it stopped")
	}
	if waited := time.Since(began); waited > 5*time.Second {
		t.Errorf("stopping a stalled keep-alive waited %s", waited)
	}
	close(stalled.unstall)
	<-keeping.finished
	_ = conn.Close()
}

// A connection whose keep-alive answers after the release gave up on it is
// closed, never pooled: its session still holds the lock, and a pooled
// connection would carry it to whichever query took it next.
func TestALockConnectionAbandonedByTheReleaseIsClosed(t *testing.T) {
	stalled := &stallingConnector{started: make(chan struct{}), unstall: make(chan struct{})}
	db := sql.OpenDB(stalled)
	defer func() { _ = db.Close() }()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	restore := keepAliveEvery
	keepAliveEvery = 10 * time.Millisecond
	t.Cleanup(func() { keepAliveEvery = restore })

	keeping := keepAlive(t.Context(), conn)
	<-stalled.started
	bounded, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := keeping.stop(bounded); err == nil {
		t.Fatal("stopping a keep-alive whose use is stalled answered that it stopped")
	}
	abandon(keeping, conn)
	close(stalled.unstall)

	deadline := time.Now().Add(5 * time.Second)
	for stalled.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if stalled.closed.Load() == 0 {
		t.Error("the connection holding the lock went back to the pool once its use answered")
	}
	if open := db.Stats().OpenConnections; open != 0 {
		t.Errorf("the pool holds %d connections after the lock's was abandoned", open)
	}
}

// The release is given a deadline of its own, whatever the migration's
// context, so a stalled connection cannot hold the start after the work is
// done.
func TestTheReleaseHasADeadline(t *testing.T) {
	var deadlined bool
	err := releaseWithin(context.Background(), func(ctx context.Context) error {
		_, deadlined = ctx.Deadline()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !deadlined {
		t.Error("the release of the migration lock carried no deadline")
	}
}

// stallingConnector is a driver, and its own connector, whose every
// statement waits until unstalled.
type stallingConnector struct {
	once    sync.Once
	started chan struct{}
	unstall chan struct{}
	closed  atomic.Int32
}

func (s *stallingConnector) Open(string) (driver.Conn, error) { return stallingConn{s}, nil }
func (s *stallingConnector) Connect(context.Context) (driver.Conn, error) {
	return stallingConn{s}, nil
}
func (s *stallingConnector) Driver() driver.Driver { return s }

type stallingConn struct{ s *stallingConnector }

func (c stallingConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c stallingConn) Close() error                        { c.s.closed.Add(1); return nil }
func (c stallingConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func (c stallingConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.s.once.Do(func() { close(c.s.started) })
	<-c.s.unstall
	return driver.RowsAffected(0), nil
}

// contextRecorder is a driver, and its own connector, that records whether a
// statement's context carried a deadline.
type contextRecorder struct {
	mu        sync.Mutex
	count     int
	deadlined bool
}

func (r *contextRecorder) uses() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

func (r *contextRecorder) Open(string) (driver.Conn, error) { return recorderConn{r}, nil }

func (r *contextRecorder) Connect(context.Context) (driver.Conn, error) {
	return recorderConn{r}, nil
}

func (r *contextRecorder) Driver() driver.Driver { return r }

type recorderConn struct{ r *contextRecorder }

func (c recorderConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c recorderConn) Close() error                        { return nil }
func (c recorderConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func (c recorderConn) ExecContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Result, error) {
	c.r.mu.Lock()
	defer c.r.mu.Unlock()
	c.r.count++
	if _, ok := ctx.Deadline(); ok {
		c.r.deadlined = true
	}
	return driver.RowsAffected(0), nil
}
