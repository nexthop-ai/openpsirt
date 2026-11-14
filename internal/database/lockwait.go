// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"modernc.org/sqlite"
)

// Executor runs a statement: a transaction of the driver's own, or one of
// bun's.
type Executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Querier answers rows: a transaction of the driver's own, or its pool.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// BoundLockWait bounds every wait for a lock the next statements on a
// transaction's connection make, to seconds.
//
// A data-definition statement waiting for a table queues every later
// statement from another session on that table behind it, on the three
// servers, for as long as it waits. Bounded, the queue lasts one attempt.
// PostgreSQL's bound is the transaction's own and ends with it, so on
// PostgreSQL tx is a transaction: outside one the server only warns and
// bounds nothing. MySQL and MariaDB's is the session's: the session's own
// value is kept beside it, and LiftLockWait puts that back before the
// connection goes back to the pool, so a bound the URL set survives.
// SQLite is bounded by its busy timeout, set in the URL every connection
// opens with, and takes nothing here.
//
// Seconds below one is refused: zero is no bound at all on PostgreSQL, and
// MySQL and MariaDB raise it to one.
func BoundLockWait(ctx context.Context, tx Executor, engine Engine, seconds int) error {
	if seconds < 1 {
		return fmt.Errorf("a lock wait bound of %d seconds bounds nothing", seconds)
	}
	var stmt string
	switch engine {
	case Postgres:
		stmt = fmt.Sprintf("SET LOCAL lock_timeout = '%ds'", seconds)
	case MySQL, MariaDB:
		stmt = fmt.Sprintf("SET @openpsirt_lock_wait = @@SESSION.lock_wait_timeout, "+
			"SESSION lock_wait_timeout = %d", seconds)
	default:
		return nil
	}
	if _, err := tx.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("bound the wait for a lock: %w", err)
	}
	return nil
}

// LiftLockWait puts back the session's own bound that BoundLockWait kept, on
// MySQL and MariaDB. PostgreSQL's ends with the transaction and SQLite has
// none, so on those two it does nothing.
func LiftLockWait(ctx context.Context, tx Executor, engine Engine) error {
	if engine != MySQL && engine != MariaDB {
		return nil
	}
	if _, err := tx.ExecContext(ctx, "SET SESSION lock_wait_timeout = @openpsirt_lock_wait"); err != nil {
		return fmt.Errorf("lift the bound on the wait for a lock: %w", err)
	}
	return nil
}

// LockWaitEnded reports whether a statement's wait for a lock another
// session holds was ended: by its bound passing, on PostgreSQL, MySQL and
// MariaDB, or by SQLite's busy timeout passing; or by the server choosing it
// as a deadlock's victim, as when a holder reads a table a migration waiting
// behind it had already taken. A data-definition statement ended either way
// changed nothing, and running it again once the holder lets go is safe. A
// deadlock on MySQL and MariaDB rolls back the whole transaction, so other
// statements are run again only with the transaction they belong to.
//
// SQLITE_LOCKED is left out: without a shared cache it is a conflict on the
// statement's own connection, which no wait resolves.
func LockWaitEnded(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "55P03" || // lock not available
			pg.Code == "40P01" // deadlock detected
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1205 || // lock wait timeout exceeded
			my.Number == 1213 // deadlock found
	}
	var lite *sqlite.Error
	if errors.As(err, &lite) {
		return lite.Code()&0xff == 5 // SQLITE_BUSY
	}
	return false
}

// holdersShown caps how many sessions Holders names.
const holdersShown = 20

// Holders names every other session on this database with a transaction
// open, oldest first: on PostgreSQL its process, user, application, state and
// when the transaction began, and on MySQL and MariaDB its connection, user,
// command and when the transaction began. PostgreSQL shows another role's
// state and times only to a role allowed to read every session's statistics,
// so a session it hides, idle or not, is named after the open transactions.
// MySQL and MariaDB list open transactions only to an account allowed to see
// every process. Where none is listed, every other session on the database
// the account can see is named instead, idle ones included: an account
// without that privilege sees its own alone. That list carries the
// migrating instance's own pooled sessions, the one holding the migration
// lock among them. Where nothing is named and a
// query was refused, the refusal is said in its place, so a wait is never
// reported with nothing beside it.
//
// A table's holder is not asked for by name: a wait that ended has released
// nothing of its own to point at, and a long transaction holding the table
// sorts with the oldest whichever table it holds. A session PostgreSQL hides
// sorts after every open transaction shown, so past twenty of those it is
// counted and left unnamed.
func Holders(ctx context.Context, q Querier, engine Engine) []string {
	var asks []string
	switch engine {
	case Postgres:
		// A role that may not read every session's statistics sees another
		// role's session with its state, times and backend type hidden, so a
		// hidden session is listed beside the open transactions, after them.
		asks = []string{`SELECT CONCAT("pid", ' ', COALESCE("usename", ''), ' ', COALESCE("application_name", ''), ' ',
				COALESCE("state", 'state hidden'), ' since ', COALESCE("xact_start"::text, 'a time hidden'))
			FROM "pg_catalog"."pg_stat_activity"
			WHERE "datname" = current_database() AND "pid" <> pg_backend_pid()
			  AND ("backend_type" IN ('client backend', 'autovacuum worker') OR "backend_type" IS NULL)
			  AND ("xact_start" IS NOT NULL OR "state" IS NULL)
			ORDER BY "xact_start" NULLS LAST, "pid"`}
	case MySQL, MariaDB:
		asks = []string{`SELECT CONCAT("p"."ID", ' ', "p"."USER", ' ', "p"."COMMAND", ' since ', "t"."trx_started")
			FROM "information_schema"."INNODB_TRX" AS "t"
			JOIN "information_schema"."PROCESSLIST" AS "p" ON "p"."ID" = "t"."trx_mysql_thread_id"
			WHERE "p"."DB" = DATABASE() AND "p"."ID" <> CONNECTION_ID()
			ORDER BY "t"."trx_started"`,
			`SELECT CONCAT("ID", ' ', "USER", ' ', "COMMAND", ' ', "TIME", 's')
			FROM "information_schema"."PROCESSLIST"
			WHERE "DB" = DATABASE() AND "ID" <> CONNECTION_ID()
			ORDER BY "TIME" DESC`}
	default:
		return []string{"nothing this session can see"}
	}
	var failed []error
	for _, ask := range asks {
		out, err := column(ctx, q, ask)
		if err != nil {
			failed = append(failed, err)
			continue
		}
		if len(out) == 0 {
			continue
		}
		if len(out) > holdersShown {
			out = append(out[:holdersShown], fmt.Sprintf("and %d more", len(out)-holdersShown))
		}
		return out
	}
	if len(failed) > 0 {
		return []string{"could not be read: " + errors.Join(failed...).Error()}
	}
	return []string{"nothing this session can see"}
}

// column answers one column of text rows.
func column(ctx context.Context, q Querier, query string) ([]string, error) {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var line sql.NullString
		if err := rows.Scan(&line); err != nil {
			return nil, err
		}
		out = append(out, line.String)
	}
	return out, rows.Err()
}
