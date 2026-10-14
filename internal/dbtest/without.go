// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Without is a migrated database of the test's own with one table removed, so
// every statement naming that table fails while every other statement works.
//
// A read that could not be made, after the reads before it succeeded, is the
// case it exists for. A store that takes that failure for a row not being
// there answers "nobody", "not here" or "not allowed" over an outage, and a
// database that is wholly unreachable cannot show it: the first statement
// fails, and every arm after it is never reached. SQLite underneath, because
// telling a failed read from an absent row does not vary by engine.
func Without(t *testing.T, table string) *database.DB {
	t.Helper()
	handle, _ := Racing(t, nil)
	if _, err := handle.ExecContext(t.Context(),
		`DROP TABLE "`+table+`"`); err != nil {
		t.Fatalf("remove %s: %v", table, err)
	}
	return handle
}
