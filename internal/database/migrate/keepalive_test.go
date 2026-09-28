// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrate

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"sync"
	"testing"
	"time"
)

// The keep-alive's use of the lock's connection carries no deadline and
// outlives the migration's context. Both drivers close a connection whose
// query outlived its context, and closing the connection releases the lock, so
// a use that can time out is one a network stall turns into a lost lock.
func TestTheKeepAliveUseHasNoDeadline(t *testing.T) {
	recorded := &contextRecorder{}
	sql.Register("keepalive-recorder", recorded)
	db, err := sql.Open("keepalive-recorder", "")
	if err != nil {
		t.Fatal(err)
	}
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
	stop := keepAlive(ctx, conn)
	deadline := time.Now().Add(5 * time.Second)
	for recorded.uses() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	stop()

	if recorded.uses() == 0 {
		t.Fatal("the keep-alive never used the connection")
	}
	if recorded.deadlined {
		t.Error("a keep-alive use carried a deadline, which closes the connection holding the lock")
	}
}

// contextRecorder is a driver that records whether a statement's context
// carried a deadline.
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
