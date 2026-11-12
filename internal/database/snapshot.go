// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/uptrace/bun"
)

// Snapshot runs fn against one consistent view of the database: every
// statement fn makes through the handle it is given reads what had been
// committed when the first of them ran, whatever is written meanwhile.
//
// For a read made of many statements that must agree with each other, such as
// a file written a page at a time, where a row written between two pages would
// otherwise be skipped or written twice.
//
// Read only, and the one transaction outside InTransaction. It writes nothing,
// so nothing certifies it at COMMIT and it has no race to lose; and what fn
// does with each statement's rows has usually left the process by the time
// any later statement could fail, so it cannot be run again. It ends by
// rolling back.
//
// Every engine takes the same options. SQLite begins a read-only transaction
// deferred, never with the write lock every other transaction takes as it
// begins, so a snapshot never holds a writer up; in WAL mode its first read
// fixes what it sees.
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
	err = fn(ctx, tx)
	if done := tx.Rollback(); done != nil && !errors.Is(done, sql.ErrTxDone) && err == nil {
		err = fmt.Errorf("end a snapshot: %w", done)
	}
	return err
}
