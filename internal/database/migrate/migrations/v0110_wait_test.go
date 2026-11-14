// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate/migrations"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// The v0.11.0 renames put back the lock wait the session carried before them,
// such as one its URL set, never the server's default. The connection goes
// back to the pool afterwards.
func TestTheV0110RenamesPutBackTheSessionsOwnLockWait(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if db.Server.Engine != database.MySQL && db.Server.Engine != database.MariaDB {
			t.Skip("the bound is the transaction's own on PostgreSQL, and SQLite sets none")
		}
		ctx := t.Context()
		tx, err := db.DB.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		// The value the connection opened with, put back for its next user:
		// the harness's URL sets one, and the server's default is not it.
		var opened int
		if err := tx.QueryRowContext(ctx, "SELECT @@SESSION.lock_wait_timeout").Scan(&opened); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, "SET SESSION lock_wait_timeout = 777"); err != nil {
			t.Fatal(err)
		}
		if err := migrations.BoundV0110Renames(ctx, tx, db.Server.Engine); err != nil {
			t.Fatal(err)
		}
		var wait int
		if err := tx.QueryRowContext(ctx, "SELECT @@SESSION.lock_wait_timeout").Scan(&wait); err != nil {
			t.Fatal(err)
		}
		if wait != 777 {
			t.Errorf("the session's lock wait after the renames is %d, want the 777 it carried", wait)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET SESSION lock_wait_timeout = %d", opened)); err != nil {
			t.Fatal(err)
		}
	})
}
