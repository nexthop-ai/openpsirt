// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

// quoting is a driver whose every statement fails with an error quoting the
// password it was given.
type quoting struct{ password string }

func (q quoting) Connect(context.Context) (driver.Conn, error) { return quotingConn(q), nil }
func (q quoting) Driver() driver.Driver                        { return nil }

type quotingConn quoting

func (q quotingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("statement refused for password " + q.password)
}
func (quotingConn) Close() error              { return nil }
func (quotingConn) Begin() (driver.Tx, error) { return nil, errors.New("no transactions") }

func TestAVersionQueryFailureIsScrubbedOfTheCredential(t *testing.T) {
	target, err := ParseURL("postgres://app:hunter2@db:5432/x?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool := sql.OpenDB(quoting{password: "hunter2"})
	t.Cleanup(func() { _ = pool.Close() })
	_, err = identify(t.Context(), pool, target)
	if err == nil {
		t.Fatal("a failing version query was answered")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("the error carries the password: %v", err)
	}
}

// Narrowing the open limit lowers the idle limit to match, and widening it
// again does not raise it. Put back with no idle limit applied, the pool keeps
// as many idle as it may open.
func TestTheIdleLimitIsPutBackAfterTheOpenLimitWasNarrowed(t *testing.T) {
	pool := sql.OpenDB(quoting{password: "x"})
	t.Cleanup(func() { _ = pool.Close() })
	db := &DB{DB: bun.NewDB(pool, sqlitedialect.New())}
	db.SetMaxOpenConns(1)
	db.SetMaxOpenConns(4)
	db.RestoreIdle()
	var held []*sql.Conn
	for range 3 {
		conn, err := pool.Conn(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	for _, conn := range held {
		_ = conn.Close()
	}
	if idle := pool.Stats().Idle; idle != 3 {
		t.Errorf("%d connections stayed idle of 3 returned, under an open limit of 4", idle)
	}
}
