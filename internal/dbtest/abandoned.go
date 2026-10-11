// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// StopAbandoned stops every statement still running against the test's
// database on another connection, and returns once none is, for a measurement
// that bounds a statement and goes on to the next.
//
// A statement abandoned by its context keeps running on MySQL and MariaDB: the
// driver closes the connection, and a statement that is working notices only
// when it has a row to send. The next reading is then taken beside it, and a filter timed after
// a runaway reads as a runaway too. PostgreSQL's driver sends a cancel request
// as the context ends, which the server acts on in its own time, so it is asked
// the same way. SQLite runs in this process and stops on the context.
//
// A server database belongs to one test binary at a time, and its tests run
// one after another, so a statement running there on another connection is
// one this test abandoned.
func StopAbandoned(t *testing.T, db *database.DB) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		ids := running(t, db)
		if len(ids) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d abandoned statements were still running after 30 s", len(ids))
		}
		for _, id := range ids {
			stop(t, db, id)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// running is the connections of the server, other than the one asking, with a
// statement running against the test's database.
func running(t *testing.T, db *database.DB) []int64 {
	t.Helper()
	var query string
	switch db.Server.Engine {
	case database.SQLite:
		return nil
	case database.Postgres:
		query = `SELECT "pid" FROM "pg_stat_activity"` +
			` WHERE "datname" = current_database() AND "pid" <> pg_backend_pid() AND "state" = 'active'`
	default:
		query = `SELECT "ID" FROM "information_schema"."PROCESSLIST"` +
			` WHERE "DB" = DATABASE() AND "ID" <> CONNECTION_ID() AND "COMMAND" = 'Query'`
	}
	var ids []int64
	if err := db.NewRaw(query).Scan(t.Context(), &ids); err != nil {
		t.Fatalf("list the statements running on %s: %v", db.Server.Engine, err)
	}
	return ids
}

// stop asks the server to end the statement a connection is running, leaving
// the connection.
func stop(t *testing.T, db *database.DB, id int64) {
	t.Helper()
	query := "SELECT pg_cancel_backend(?)"
	if db.Server.Engine != database.Postgres {
		query = "KILL QUERY ?"
	}
	// A statement that ends between the listing and this is no longer there to
	// stop, which MySQL and MariaDB report as an error about the connection.
	if _, err := db.ExecContext(t.Context(), query, id); err != nil {
		t.Logf("stop the statement on connection %d: %v", id, err)
	}
}
