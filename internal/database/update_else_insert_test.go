// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"errors"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A write that ends a PostgreSQL transaction on a lost race is refused inside
// one, before any statement is built or run.
func TestUpdateElseInsertIsRefusedInsideATransaction(t *testing.T) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		tx, err := db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		built := false
		err = database.UpdateElseInsert(t.Context(), tx,
			func(bun.IDB) *bun.UpdateQuery { built = true; return nil },
			func(bun.IDB) *bun.InsertQuery { built = true; return nil })
		if !errors.Is(err, database.ErrInsideTransaction) {
			t.Errorf("inside a transaction it answered %v", err)
		}
		if built {
			t.Error("a statement was built inside a transaction")
		}
	})
}
