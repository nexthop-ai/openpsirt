// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// settingDriver records every statement run and refuses one by its text.
type settingDriver struct {
	mu      sync.Mutex
	ran     []string
	refuses string
}

func (d *settingDriver) Open(string) (driver.Conn, error) { return settingConn{d}, nil }

type settingConn struct{ d *settingDriver }

func (c settingConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not prepared") }
func (c settingConn) Close() error                        { return nil }
func (c settingConn) Begin() (driver.Tx, error)           { return settingTx{}, nil }

func (c settingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	c.d.ran = append(c.d.ran, query)
	if c.d.refuses != "" && strings.Contains(query, c.d.refuses) {
		return nil, errors.New("refused")
	}
	return driver.RowsAffected(0), nil
}

type settingTx struct{}

func (settingTx) Commit() error   { return nil }
func (settingTx) Rollback() error { return nil }

// renamerOver is a MySQL renamer over the recording driver.
func renamerOver(t *testing.T, d *settingDriver) renamer {
	t.Helper()
	sql.Register("setting-"+t.Name(), d)
	db, err := sql.Open("setting-"+t.Name(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return renamer{u: &upgrader{ctx: t.Context(), raw: tx, engine: database.MySQL}}
}

// A bound applied only in part is put back before the failure is reported,
// because the connection goes back to the pool with whatever it holds.
func TestABoundAppliedInPartIsPutBack(t *testing.T) {
	d := &settingDriver{refuses: "foreign_key_checks = 0"}
	if _, err := renamerOver(t, d).bound(); err == nil {
		t.Fatal("a bound whose second setting was refused was reported applied")
	}
	if !slices.Contains(d.ran, "SET SESSION lock_wait_timeout = DEFAULT") {
		t.Errorf("the lock wait applied before the refusal was left in place; ran %q", d.ran)
	}
	if slices.Contains(d.ran, "SET SESSION foreign_key_checks = 1") {
		t.Errorf("a setting never applied was put back; ran %q", d.ran)
	}
}

// Putting the bound back tries every setting and reports each that failed.
func TestEverySettingIsPutBackWhereOneFails(t *testing.T) {
	d := &settingDriver{}
	restore, err := renamerOver(t, d).bound()
	if err != nil {
		t.Fatal(err)
	}
	d.refuses = "lock_wait_timeout = DEFAULT"
	if err := restore(); err == nil {
		t.Error("a setting that could not be put back was not reported")
	}
	if !slices.Contains(d.ran, "SET SESSION foreign_key_checks = 1") {
		t.Errorf("foreign key checks were left off after the first reset failed; ran %q", d.ran)
	}
}
