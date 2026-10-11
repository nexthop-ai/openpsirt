// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

func TestAStatementAbandonedByItsContextIsStoppedOnTheServer(t *testing.T) {
	Each(t, func(t *testing.T, db *database.DB) {
		if db.Server.Engine == database.SQLite {
			t.Skip("SQLite runs in this process, so no statement outlives its context")
		}
		// Work rather than a wait: MySQL and MariaDB end a SLEEP on their own
		// once the client has gone, and a statement that is working does not
		// look.
		long := "SELECT BENCHMARK(100000000000, MD5('abandoned'))"
		if db.Server.Engine == database.Postgres {
			long = "SELECT pg_sleep(120)"
		}
		within, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if _, err := db.ExecContext(within, long); err == nil {
			t.Fatal("a statement of minutes finished inside a second")
		}
		StopAbandoned(t, db)
		if ids := running(t, db); len(ids) != 0 {
			t.Fatalf("connections %v still run a statement after it was abandoned and stopped", ids)
		}
	})
}
