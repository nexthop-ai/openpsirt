// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect"
)

// Snapshot runs fn against one consistent view of the database: every
// statement fn makes through the handle it is given reads what had been
// committed when the first of them ran, whatever is written meanwhile.
//
// For a read made of many statements that must agree with each other, such as
// a file written a page at a time, where a row written between two pages would
// otherwise be skipped or written twice.
//
// Begun on a database handle, never inside a transaction: a transaction
// reads at its own isolation, which on PostgreSQL is READ COMMITTED, where
// every statement sees a moving database.
//
// Read only, and the one transaction a request makes outside InTransaction;
// migrations run their own. It writes nothing, so nothing certifies it at
// COMMIT and it has no race to lose; and what fn does with each statement's
// rows has usually left the process by the time any later statement could
// fail, so it cannot be run again. It ends by rolling back.
//
// Every engine takes the same options. SQLite begins a read-only transaction
// deferred, never with the write lock every other transaction takes as it
// begins, so a snapshot never holds a writer up; in WAL mode its first read
// fixes what it sees.
//
// It sits idle between statements while fn writes what it read, and lasts as
// long as the file, so on PostgreSQL a server's bound on a session idle inside
// a transaction, or on a transaction's length, would end it partway through.
// Both are lifted for the snapshot alone, and fn's context bounds it instead.
// MySQL and MariaDB end any session idle past wait_timeout, inside a
// transaction or not; its default of eight hours is far past any export's
// ceiling, and it is left as the server sets it. MariaDB also ends a
// transaction idle past idle_transaction_timeout or
// idle_readonly_transaction_timeout, both off by default and left as the
// server sets them: it has no setting scoped to one transaction, so a lift
// would outlive the snapshot on its pooled connection.
func Snapshot(ctx context.Context, db *DB, fn func(context.Context, bun.IDB) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin a snapshot: %w", err)
	}
	if db.Dialect().Name() == dialect.PG {
		// Both bounds the server holds, read from its settings: PostgreSQL 17
		// added the second, and a name an older server does not know is
		// refused rather than ignored.
		if _, err := tx.ExecContext(ctx, `SELECT set_config("name", '0', true) FROM "pg_settings"
			WHERE "name" IN ('idle_in_transaction_session_timeout', 'transaction_timeout')`); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("lift the time bounds on a snapshot: %w", err)
		}
	}
	err = fn(ctx, tx)
	if done := tx.Rollback(); done != nil && !errors.Is(done, sql.ErrTxDone) && err == nil {
		err = fmt.Errorf("end a snapshot: %w", done)
	}
	return err
}
