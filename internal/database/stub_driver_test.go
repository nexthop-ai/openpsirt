// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
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

// A PostgreSQL pre-release is identified by its version number. The sentence
// version() returns names it "18beta1", with no dot, and the first dotted
// number in it is the compiler's.
func TestAPostgreSQLPreReleaseIsIdentifiedByItsNumber(t *testing.T) {
	target, err := ParseURL("postgres://app@db:5432/x?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool := sql.OpenDB(versionAnswer{
		sentence: "PostgreSQL 18beta1 on x86_64-pc-linux-gnu, compiled by gcc (GCC) 12.2.0",
		number:   "180000",
	})
	t.Cleanup(func() { _ = pool.Close() })
	server, err := identify(t.Context(), pool, target)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Version{18, 0, 0}); server.Version != want {
		t.Errorf("a pre-release of PostgreSQL 18 was identified as %s, want %s", server.Version, want)
	}
}

// versionAnswer is a driver answering PostgreSQL's version question with a
// sentence and a number, and refusing every other statement.
type versionAnswer struct{ sentence, number string }

func (v versionAnswer) Connect(context.Context) (driver.Conn, error) { return versionConn(v), nil }
func (v versionAnswer) Driver() driver.Driver                        { return nil }

type versionConn versionAnswer

func (versionConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (versionConn) Close() error                        { return nil }
func (versionConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

func (v versionConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "server_version_num") {
		return nil, errors.New("no answer for " + query)
	}
	return &versionRow{values: []driver.Value{v.sentence, v.number}}, nil
}

// versionRow is one row of a version and its number.
type versionRow struct {
	values []driver.Value
	done   bool
}

func (r *versionRow) Columns() []string { return []string{"version", "server_version_num"} }
func (r *versionRow) Close() error      { return nil }
func (r *versionRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	copy(dest, r.values)
	return nil
}
