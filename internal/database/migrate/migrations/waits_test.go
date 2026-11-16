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
//
// On a server the holder takes the table before the upgrade starts, as a
// paged export running at the time holds it. On SQLite a writer holding the
// file holds back the claim of the lease too, so there the holder takes the
// table once the upgrade holds its lease, during a notice long enough to take
// it.
func TestAMigrationWaitsOutAHolderWithoutStallingOtherSessions(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Empty(t, db)
		dbtest.MigrateTo(t, db, migrations.Baseline)
		noConnectionCarriesTheBound(t, db)
		dbtest.MigrateTo(t, db, v0120)
		if db.Server.Engine == database.SQLite {
			// SQLite's attempt is its busy timeout, a minute from the URL,
			// shortened here on the harness's one connection.
			shortBusy(t, db)
		}

		sqlite := db.Server.Engine == database.SQLite
		var holder *sql.Tx
		var requests *sql.DB
		var holderID string
		var notice time.Duration
		if sqlite {
			notice = 3 * time.Second
		} else {
			holder, requests, holderID = holdTable(t, db)
		}
		log := &lockedBuffer{}
		migrating := migrations.ShortLockWaits(ctx)
		done, finished := make(chan error, 1), make(chan struct{})
		go func() {
			defer close(finished)
			done <- migrate.UpTo(migrating, db, slog.New(slog.NewTextHandler(log, nil)), v0130, notice)
		}()
		t.Cleanup(func() { <-finished })
		if sqlite {
			heldToChange(t, db)
			holder, requests, holderID = holdTable(t, db)
		}
		// A test that fails part way lets the holder go before it waits for
		// the migration to end.
		t.Cleanup(func() { _ = holder.Rollback() })

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

// heldToChange waits up to half a minute for the migration lease to be held
// to change the schema, read through a handle of its own on SQLite, whose
// harness gives the migration its one connection.
func heldToChange(t *testing.T, db *database.DB) {
	t.Helper()
	reading := servingBeside(t, db)
	deadline := time.Now().Add(30 * time.Second)
	for {
		var holding string
		err := reading.QueryRowContext(t.Context(), `SELECT "holding" FROM "`+migrate.LeaseTable+`"`).Scan(&holding)
		if err == nil && holding == "change" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the migration did not hold its lease to change the schema within 30s: %q, %v", holding, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
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
//
// Each is held to a connection the pool opens fresh, because the URL may set
// the session's bound, as the harness's does on MySQL and MariaDB, and the
// session's own value is what a migration puts back.
func noConnectionCarriesTheBound(t *testing.T, db *database.DB) {
	t.Helper()
	ctx := t.Context()
	asking := `SELECT @@SESSION.lock_wait_timeout`
	switch db.Server.Engine {
	case database.SQLite:
		return
	case database.Postgres:
		asking = `SELECT current_setting('lock_timeout')`
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
	// Every connection the pool holds is taken before the fresh one, so the
	// pool has none idle to hand back for it.
	var said []string
	for range open + 1 {
		conn, err := db.DB.DB.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
		var value string
		if err := conn.QueryRowContext(ctx, asking).Scan(&value); err != nil {
			t.Fatal(err)
		}
		said = append(said, value)
	}
	fresh, pooled := said[open], said[:open]
	for _, value := range pooled {
		if value != fresh {
			t.Errorf("a connection went back to the pool carrying a migration's bound on a lock wait: %s, where a fresh one says %s",
				value, fresh)
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
