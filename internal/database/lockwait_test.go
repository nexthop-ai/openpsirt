// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A lock wait ended by its bound or as a deadlock is told from every other
// failure, on each engine, because a migration tries again on the one and
// gives up on the rest.
func TestALockWaitEndedIsToldFromOtherFailures(t *testing.T) {
	for _, c := range []struct {
		what   string
		err    error
		waited bool
	}{
		{"PostgreSQL's bound passing", fmt.Errorf("alter: %w", &pgconn.PgError{Code: "55P03"}), true},
		{"MySQL's bound passing", fmt.Errorf("alter: %w", &mysql.MySQLError{Number: 1205}), true},
		{"a PostgreSQL deadlock", &pgconn.PgError{Code: "40P01"}, true},
		{"a MySQL deadlock", &mysql.MySQLError{Number: 1213}, true},
		{"a PostgreSQL serialization failure", &pgconn.PgError{Code: "40001"}, false},
		{"a MySQL duplicate column", &mysql.MySQLError{Number: 1060}, false},
		{"a sentence naming a lock", errors.New("lock wait timeout exceeded"), false},
		{"nothing at all", nil, false},
	} {
		if got := database.LockWaitEnded(c.err); got != c.waited {
			t.Errorf("%s: read as a lock wait ended: %v, want %v", c.what, got, c.waited)
		}
	}
}

// SQLite's busy timeout passing, while another connection holds the write
// lock, is a lock wait ended.
func TestSQLitesBusyTimeoutPassingIsALockWaitEnded(t *testing.T) {
	ctx := t.Context()
	url := "sqlite://" + filepath.Join(t.TempDir(), "busy.db")
	open := func(url string) *database.DB {
		target, err := database.ParseURL(url)
		if err != nil {
			t.Fatal(err)
		}
		db, err := database.Open(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	holder := open(url)
	if _, err := holder.ExecContext(ctx, `CREATE TABLE "t" ("n" INTEGER)`); err != nil {
		t.Fatal(err)
	}
	held, err := holder.DB.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Rollback() })
	if _, err := held.ExecContext(ctx, `INSERT INTO "t" ("n") VALUES (1)`); err != nil {
		t.Fatal(err)
	}

	// The waiter's timeout is a tenth of a second, on every connection it
	// opens.
	waiter := open(url + "?_pragma=busy_timeout(100)")
	_, err = waiter.ExecContext(ctx, `INSERT INTO "t" ("n") VALUES (2)`)
	if err == nil {
		t.Fatal("a write went through while another connection held the write lock")
	}
	if !database.LockWaitEnded(err) {
		t.Errorf("SQLite's busy timeout passing was not read as a lock wait ended: %v", err)
	}
}

// A bound the session already carried, as one a URL sets does, is the bound it
// carries once the bound a statement took is lifted.
func TestASessionsOwnLockWaitBoundIsPutBack(t *testing.T) {
	dbtest.Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		set, reset, read := `SET SESSION lock_wait_timeout = 77`, `SET SESSION lock_wait_timeout = DEFAULT`,
			`SELECT CAST(@@SESSION.lock_wait_timeout AS CHAR)`
		want := "77"
		if db.Server.Engine == database.Postgres {
			set, reset, read, want = `SET lock_timeout = '77s'`, `RESET lock_timeout`, `SHOW lock_timeout`, "77s"
		}
		t.Cleanup(func() {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), reset)
			_ = conn.Close()
		})
		if _, err := conn.ExecContext(ctx, set); err != nil {
			t.Fatal(err)
		}
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := database.BoundLockWait(ctx, tx, db.Server.Engine, 1); err != nil {
			t.Fatal(err)
		}
		if err := database.LiftLockWait(ctx, tx, db.Server.Engine); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		var got string
		if err := conn.QueryRowContext(ctx, read).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("the session carries a lock wait bound of %s once the statement's is lifted, want %s", got, want)
		}
	})
}

// A PostgreSQL role that may not read every session's statistics sees another
// role's session with its state and backend type hidden, and Holders still
// names it.
func TestHoldersNamesASessionPostgreSQLHides(t *testing.T) {
	dbtest.Only(t, database.Postgres, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		// Roles belong to the server, so test binaries running at once
		// may each create this one; the one that loses the race finds it made.
		if _, err := db.ExecContext(ctx, `DO $$ BEGIN
				CREATE ROLE "openpsirt_unprivileged_observer" NOLOGIN;
			EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
			END $$`); err != nil {
			t.Fatal(err)
		}
		holder, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = holder.Close() })
		held, err := holder.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = held.Rollback() })
		var pid string
		if err := held.QueryRowContext(ctx, `SELECT pg_backend_pid()::text`).Scan(&pid); err != nil {
			t.Fatal(err)
		}

		observer, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = observer.ExecContext(context.WithoutCancel(ctx), `RESET ROLE`)
			_ = observer.Close()
		})
		if _, err := observer.ExecContext(ctx, `SET ROLE "openpsirt_unprivileged_observer"`); err != nil {
			t.Fatal(err)
		}
		var hidden bool
		if err := observer.QueryRowContext(ctx, `SELECT "backend_type" IS NULL
			FROM "pg_catalog"."pg_stat_activity" WHERE "pid"::text = ?`, pid).Scan(&hidden); err != nil {
			t.Fatal(err)
		}
		if !hidden {
			t.Fatal("the observer sees the holder's backend type, so this checks nothing")
		}
		named := database.Holders(ctx, observer, database.Postgres)
		for _, h := range named {
			if strings.HasPrefix(h, pid+" ") {
				return
			}
		}
		t.Errorf("the holder %s is not among the sessions named: %q", pid, named)
	})
}
