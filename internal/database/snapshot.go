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
// Read only, and the one transaction a request makes outside InTransaction;
// migrations run their own. It writes nothing,
// so nothing certifies it at COMMIT and it has no race to lose; and what fn
// does with each statement's rows has usually left the process by the time
// any later statement could fail, so it cannot be run again. It ends by
// rolling back.
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
func Snapshot(ctx context.Context, db bun.IDB, fn func(context.Context, bun.IDB) error) error {
	if tx, inside := db.(bun.Tx); inside {
		// Already inside a transaction, which is a view of its own.
		return fn(ctx, tx)
	}
	handle, ok := Handle(db)
	if !ok {
		return fmt.Errorf("a snapshot: %T is neither a database handle nor a transaction", db)
	}
	tx, err := handle.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin a snapshot: %w", err)
	}
	if handle.Dialect().Name() == dialect.PG {
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
