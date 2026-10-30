// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A rival blocked on a row the transaction under test holds lets the
// transaction go on once the server reports the wait, well inside the bound,
// and lands once the transaction commits.
//
// Verified by asking lockWaiter nothing: the write then waits out the bound
// and the time below fails.
func TestARivalHeldOnALockLetsTheTransactionGoOnBeforeItsBound(t *testing.T) {
	Servers(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		if _, err := db.ExecContext(ctx, `INSERT INTO "application_setting" ("name", "value", "updated_at")
			VALUES (?, ?, ?)`, "dbtest.rival", "first", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		const bound = 10 * time.Second
		hooked, rival := RivalAfterRead(t, db, "application_setting", "application_setting", bound, func() error {
			_, err := db.ExecContext(context.Background(),
				`UPDATE "application_setting" SET "value" = 'rival' WHERE "name" = 'dbtest.rival'`)
			return err
		})
		started := time.Now()
		if err := database.InTransaction(ctx, hooked, func(ctx context.Context, tx bun.Tx) error {
			if _, err := tx.ExecContext(ctx,
				`SELECT "value" FROM "application_setting" WHERE "name" = 'dbtest.rival' FOR UPDATE`); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx,
				`UPDATE "application_setting" SET "value" = 'held' WHERE "name" = 'dbtest.rival'`)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if took := time.Since(started); took > bound/2 {
			t.Errorf("the transaction went on after %s, past half its bound of %s, with its rival held", took, bound)
		}
		if err := rival(); err != nil {
			t.Fatal(err)
		}
		var value string
		if err := db.QueryRowContext(ctx,
			`SELECT "value" FROM "application_setting" WHERE "name" = 'dbtest.rival'`).Scan(&value); err != nil {
			t.Fatal(err)
		}
		if value != "rival" {
			t.Errorf("the setting reads %q, want the rival's write landed after the commit", value)
		}
	})
}
