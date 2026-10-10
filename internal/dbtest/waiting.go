// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// waitingBound is how long UntilWaitingOnALock looks before it reports that
// nothing came to wait.
const waitingBound = 10 * time.Second

// UntilWaitingOnALock returns once a session on db's database is waiting on a
// lock another session holds, which is the moment a test racing two writers
// lets the first commit. It fails the test when none comes to wait within a
// bound.
//
// Each server keeps who is waiting somewhere of its own: PostgreSQL in its
// activity view, and MySQL and MariaDB in InnoDB's transaction table, joined to
// the process list to keep to this database, because the servers are shared by
// every package running at once. InnoDB refreshes that table only when it has
// gone unread for a tenth of a second, so it is asked less often than that.
// SQLite has no session that waits on another's row, so it is refused.
func UntilWaitingOnALock(t *testing.T, db *database.DB) {
	t.Helper()
	var query string
	every := 5 * time.Millisecond
	switch db.Server.Engine {
	case database.Postgres:
		query = `SELECT count(*) FROM "pg_stat_activity"
			WHERE "datname" = current_database() AND "wait_event_type" = 'Lock'`
	case database.MySQL, database.MariaDB:
		query = `SELECT count(*) FROM "information_schema"."innodb_trx" AS "waiter"
			JOIN "information_schema"."processlist" AS "session"
				ON "session"."id" = "waiter"."trx_mysql_thread_id"
			WHERE "waiter"."trx_state" = 'LOCK WAIT' AND "session"."db" = DATABASE()`
		every = 150 * time.Millisecond
	default:
		t.Fatalf("%s has no session that waits on another's lock", db.Server.Engine)
	}
	ctx := t.Context()
	deadline := time.Now().Add(waitingBound)
	for {
		var waiting int
		if err := db.NewRaw(query).Scan(ctx, &waiting); err != nil {
			t.Fatalf("ask %s who is waiting: %v", db.Server.Engine, err)
		}
		if waiting > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no session came to wait on a lock within %s", waitingBound)
		}
		time.Sleep(every)
	}
}
