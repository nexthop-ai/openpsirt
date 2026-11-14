// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// waiting is the line a migration logs for each attempt that waits out its
// bound.
const waiting = "a migration is waiting for a table something else holds"

// A migration whose table another session holds, as a paged export's
// snapshot holds every table it has read, waits for the holder through
// several attempts and then applies, and another session's statement on the
// table waits at most one attempt while it does. On SQLite the holder is a writer, the busy
// timeout bounds each attempt, and a reader goes through beside the writer.
func TestAMigrationWaitsOutAHolderWithoutStallingOtherSessions(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, migrations.Baseline)
		noConnectionCarriesTheBound(t, db)
		dbtest.MigrateTo(t, db, v0120)

		holder, requests, holderID := holdTable(t, db)
		if db.Server.Engine == database.SQLite {
			// SQLite's attempt is its busy timeout, a minute from the URL,
			// shortened here on the harness's one connection.
			shortBusy(t, db)
		}

		log := &lockedBuffer{}
		migrating := migrations.ShortLockWaits(ctx)
		done, finished := make(chan error, 1), make(chan struct{})
		go func() {
			defer close(finished)
			done <- migrate.UpTo(migrating, db, slog.New(slog.NewTextHandler(log, nil)), v0130)
		}()
		// A test that fails part way lets the holder go and waits for the
		// migration to end before the test does.
		t.Cleanup(func() {
			_ = holder.Rollback()
			<-finished
		})

		// Requests on the table keep going through for as long as the
		// holder holds it: each waits one attempt at most.
		const attempts = 3
		started := time.Now()
		for {
			asking, cancel := context.WithTimeout(ctx, 3*time.Second)
			var n int
			err := requests.QueryRowContext(asking, `SELECT COUNT(*) FROM "`+held+`"`).Scan(&n)
			cancel()
			if err != nil {
				t.Fatalf("a request on the table waited behind the migration: %v", err)
			}
			select {
			case err := <-done:
				t.Fatalf("the migration ended while the holder held its table: %v", err)
			default:
			}
			if strings.Count(log.String(), waiting) >= attempts {
				break
			}
			if time.Since(started) > 30*time.Second {
				t.Fatalf("the migration logged %d waits, not %d; it said:\n%s",
					strings.Count(log.String(), waiting), attempts, log)
			}
			time.Sleep(100 * time.Millisecond)
		}
		// The holder began its transaction first, so it heads the list.
		if db.Server.Engine != database.SQLite && !strings.Contains(log.String(), `held_by="[`+holderID+" ") {
			t.Errorf("the wait did not name the session holding the table, %s; it said:\n%s", holderID, log)
		}

		if err := holder.Commit(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("the migration failed once the holder let go: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("the migration did not apply once the holder let go")
		}
		noConnectionCarriesTheBound(t, db)
		leaveAtLatest(t, ctx, db)
	})
}

// shortBusy makes the busy timeout a tenth of a second on the one connection
// the harness gives SQLite, and keeps that connection open for the test, so
// no fresh one opens with the URL's minute. The handle is the test's own and
// closes with it.
func shortBusy(t *testing.T, db *database.DB) {
	t.Helper()
	db.SetConnMaxLifetime(0)
	if _, err := db.ExecContext(t.Context(), `PRAGMA busy_timeout = 100`); err != nil {
		t.Fatal(err)
	}
}

// noConnectionCarriesTheBound checks every connection the pool holds for a
// bound on a lock wait a migration left on its session.
func noConnectionCarriesTheBound(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	asking := `SELECT @@SESSION.lock_wait_timeout = @@GLOBAL.lock_wait_timeout`
	switch db.Server.Engine {
	case database.SQLite:
		return
	case database.Postgres:
		asking = `SELECT "setting" = "reset_val" FROM "pg_catalog"."pg_settings"
			WHERE "name" = 'lock_timeout'`
	}
	open := db.Stats().OpenConnections
	if open == 0 {
		t.Fatal("the pool holds no connection, so this checked nothing")
	}
	var held []*sql.Conn
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	}()
	for range open {
		conn, err := db.DB.DB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
		var unchanged bool
		if err := conn.QueryRowContext(ctx, asking).Scan(&unchanged); err != nil {
			t.Fatal(err)
		}
		if !unchanged {
			t.Error("a connection went back to the pool carrying a migration's bound on a lock wait")
		}
	}
}

// held is the table a test holds: one the v0.13.0 upgrade alters.
const held = "advisory_issue"

// holdTable holds that table in a transaction on a connection of its own, as a
// paged export's snapshot does on a server, or as a writer does on SQLite,
// and returns that transaction, a handle for requests made beside it, and
// how the server names the holder's session.
func holdTable(t *testing.T, db *database.DB) (*sql.Tx, *sql.DB, string) {
	t.Helper()
	ctx := t.Context()
	pool := db.DB.DB
	if db.Server.Engine == database.SQLite {
		// The harness gives SQLite one connection, which the migration
		// takes, so the holder and the requests are other processes' worth
		// of handles on the same file.
		var seq int
		var name, file string
		if err := pool.QueryRowContext(ctx, `PRAGMA database_list`).Scan(&seq, &name, &file); err != nil {
			t.Fatal(err)
		}
		pool = dbtest.Open(t, "sqlite://"+file).DB.DB
		requests := dbtest.Open(t, "sqlite://"+file).DB.DB
		tx, err := pool.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tx.Rollback() })
		if _, err := tx.ExecContext(ctx, `UPDATE "`+held+`" SET "added_at" = "added_at"`); err != nil {
			t.Fatal(err)
		}
		return tx, requests, ""
	}
	conn, err := pool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	identify := `SELECT CONNECTION_ID()`
	if db.Server.Engine == database.Postgres {
		identify = `SELECT pg_backend_pid()`
	}
	var id int64
	if err := conn.QueryRowContext(ctx, identify).Scan(&id); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM "`+held+`"`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return tx, pool, fmt.Sprint(id)
}
