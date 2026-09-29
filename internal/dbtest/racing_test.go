// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest_test

import (
	"testing"

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
