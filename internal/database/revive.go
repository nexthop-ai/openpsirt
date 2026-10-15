// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// TakeUpAgain records a row under a name that may once have been retired.
//
// A table that keeps its retired rows, because what happened under them is
// asked about afterwards, holds its names unique across those rows too. So an
// insert under a retired name fails on a row nothing lists. revive clears that
// row's retirement and writes what the new one says; where it matched a row,
// readBack reads it into the caller's model, keeping its identifier and
// everything recorded against it. Where it matched none, insert writes a new
// row.
//
// An insert refused by the unique constraint is a name in use, by a live row
// or by a writer that arrived alongside this one, and answers taken. what
// names the thing in the error text of any other failure.
func TakeUpAgain(ctx context.Context, revive *bun.UpdateQuery, readBack *bun.SelectQuery,
	insert *bun.InsertQuery, taken error, what string) error {

	res, err := revive.Exec(ctx)
	if err != nil {
		return fmt.Errorf("take that %s up again: %w", what, err)
	}
	n, err := Affected(res)
	if err != nil {
		return fmt.Errorf("take that %s up again: %w", what, err)
	}
	if n > 0 {
		if err := readBack.Scan(ctx); err != nil {
			return fmt.Errorf("read that %s back: %w", what, err)
		}
		return nil
	}
	if _, err := insert.Exec(ctx); err != nil {
		if IsDuplicate(err) {
			return taken
		}
		return fmt.Errorf("record that %s: %w", what, err)
	}
	return nil
}

// Retire dates one row of model as out of use at the moment given, and
// reports whether this write is the one that retired it.
//
// The write repeats that the row is in use, so two retirements at once record
// one act: the second matches nothing. A row already retired, and a row that
// was never there, both answer false; telling those apart is the caller's.
// The functions in also add to the write what retiring that kind of row
// clears beside the date.
func Retire(ctx context.Context, db bun.IDB, model any, id int64, at time.Time,
	also ...func(*bun.UpdateQuery) *bun.UpdateQuery) (bool, error) {

	write := db.NewUpdate().Model(model).
		Set(`"retired_at" = ?`, at).
		Where(`"id" = ?`, id).
		Where(`"retired_at" IS NULL`)
	for _, more := range also {
		write = more(write)
	}
	res, err := write.Exec(ctx)
	if err != nil {
		return false, err
	}
	n, err := Affected(res)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
