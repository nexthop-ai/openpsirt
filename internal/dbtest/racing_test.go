// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// The racing handle is SQLite as the application opens it: foreign keys
// enforced, a wait on a held lock, and the write-ahead journal. Without them a
// test on it passes against a schema whose references nothing checks.
func TestARacingHandleIsOpenedAsTheApplicationOpensSQLite(t *testing.T) {
	db, _ := dbtest.Racing(t, nil)
	ctx := t.Context()
	for pragma, want := range map[string]string{
		"foreign_keys": "1",
		"busy_timeout": "60000",
		"journal_mode": "wal",
	} {
		var got string
		if err := db.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&got); err != nil {
			t.Fatalf("%s: %v", pragma, err)
		}
		if got != want {
			t.Errorf("%s is %s, want %s", pragma, got, want)
		}
	}
}

// A read through the racing handle inside one of its own transactions waits
// for the connection the transaction holds, so a closure under a retry test
// that reads outside its transaction hangs rather than passing. The handle
// Other gives answers while the transaction is open, which is what lets the
// other worker act between attempts.
func TestARacingHandleReadsOutsideATransactionOnlyByWaitingForIt(t *testing.T) {
	db, race := dbtest.Racing(t, nil)
	err := database.InTransaction(t.Context(), db.DB, func(ctx context.Context, _ bun.Tx) error {
		outside, stop := context.WithTimeout(ctx, 200*time.Millisecond)
		defer stop()
		var one int
		if err := db.QueryRowContext(outside, "SELECT 1").Scan(&one); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("a read outside the open transaction answered %v, want it to wait", err)
		}
		if err := race.Other().QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
			t.Errorf("the other handle could not read while the transaction was open: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
