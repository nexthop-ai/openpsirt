// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// StopPast stops every statement of the database's own sessions that has run
// longer than the duration given, for a measurement that caps a statement
// rather than waiting hours on it.
//
// A driver giving up on a statement is not enough on MySQL and MariaDB, which
// run it to the end on the server; it is killed there. PostgreSQL is asked to
// cancel it as well. SQLite stops a statement in the client.
func StopPast(db *database.DB, past time.Duration) error {
	ctx := context.Background()
	seconds := int(past.Seconds())
	switch db.Server.Engine {
	case database.Postgres:
		if _, err := db.ExecContext(ctx, `SELECT pg_cancel_backend("pid") FROM "pg_catalog"."pg_stat_activity"
			WHERE "datname" = current_database() AND "pid" <> pg_backend_pid() AND "state" = 'active'
			AND "query_start" < now() - make_interval(secs => ?)`, seconds); err != nil {
			return fmt.Errorf("cancel the statements past %s: %w", past, err)
		}
	case database.MySQL, database.MariaDB:
		var running []int64
		if err := db.DB.NewRaw(`SELECT "id" FROM "information_schema"."processlist"
			WHERE "db" = DATABASE() AND "command" = 'Query' AND "id" <> CONNECTION_ID() AND "time" >= ?`,
			seconds).Scan(ctx, &running); err != nil {
			return fmt.Errorf("list the statements past %s: %w", past, err)
		}
		for _, id := range running {
			if _, err := db.ExecContext(ctx, fmt.Sprintf("KILL QUERY %d", id)); err != nil {
				return fmt.Errorf("stop statement %d: %w", id, err)
			}
		}
	}
	return nil
}
