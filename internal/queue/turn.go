// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A turn is a lease row nothing holds as a lease: writes that must not
// interleave each update it inside their transaction, and the write lock the
// update takes makes the next one wait for the first to commit, on every
// engine. A count read beside another writer's uncommitted insert does not
// see it, so a limit checked by counting is checked after taking a turn.

// EnsureTurn makes the row a turn is taken on.
//
// Outside the transaction that takes it, because a second writer's insert is
// refused by the primary key, and on PostgreSQL a refused statement aborts the
// transaction it is in.
func EnsureTurn(ctx context.Context, db bun.IDB, name string) error {
	if _, err := db.NewInsert().Model(&Lease{Name: name}).Exec(ctx); err != nil && !database.IsDuplicate(err) {
		return fmt.Errorf("record the turn %q: %w", name, err)
	}
	return nil
}

// TakeTurn makes every other transaction taking the turn name wait for this
// one.
//
// The write puts a new value in the row every time. An update setting a
// column to what it already holds is matched and not written on MySQL and
// MariaDB, and a cluster certifies only rows that were written, so two
// writers on two nodes would both pass.
func TakeTurn(ctx context.Context, tx bun.IDB, name string) error {
	if _, err := tx.NewUpdate().Model((*Lease)(nil)).
		Set(`"held_by" = ?`, rand.Text()).
		Where(`"name" = ?`, name).
		Exec(ctx); err != nil {
		return fmt.Errorf("wait for the turn %q: %w", name, err)
	}
	return nil
}
