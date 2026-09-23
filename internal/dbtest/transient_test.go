// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// TestATestConnectionDoesNotWaitForACommitToReachDisk pins the setting each
// engine is asked for, on the connection a test is handed.
//
// The saving is most of the run — the three server engines take 240 s with
// durability on and 77 s without — and it is invisible when it goes: a
// connection string built a different way, or a pragma dropped, leaves every
// test passing and the suite three times slower. Read back from the session
// rather than from the container's command line, because what matters is the
// connection a test got.
func TestATestConnectionDoesNotWaitForACommitToReachDisk(t *testing.T) {
	Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		switch engine := db.Server.Engine; engine {
		case database.Postgres:
			// Asked for in the connection string, so the server is left as it
			// is and a session gets it for itself.
			var setting string
			if err := db.QueryRowContext(ctx, `SHOW synchronous_commit`).Scan(&setting); err != nil {
				t.Fatalf("read synchronous_commit: %v", err)
			}
			if setting != "off" {
				t.Errorf("synchronous_commit is %q, so every commit waits for the log to reach disk", setting)
			}
		case database.MySQL, database.MariaDB:
			// Global on this protocol, so the harness sets it on the server.
			// Read before anything is written, because a read that repairs
			// what it is checking cannot fail.
			var flush, binlog int
			if err := db.QueryRowContext(ctx,
				`SELECT @@innodb_flush_log_at_trx_commit, @@sync_binlog`).Scan(&flush, &binlog); err != nil {
				t.Fatalf("read the durability settings: %v", err)
			}
			if flush == 0 && binlog == 0 {
				return
			}
			// Still durable, and the two reasons are different: a connection
			// that may not set a global is one the suite runs on anyway, and
			// one that may is a harness that stopped asking.
			//
			// Asked by writing back the value the server already holds. A
			// probe that sets the relaxed value repairs what it is checking,
			// and a server kept between runs then reads both zeros and passes
			// with the harness still silent.
			if _, err := db.ExecContext(ctx,
				`SET GLOBAL innodb_flush_log_at_trx_commit = ?`, flush); err != nil {
				t.Skipf("this connection may not set a global, so the server keeps its own durability: %v", err)
			}
			t.Errorf("innodb_flush_log_at_trx_commit is %d and sync_binlog is %d on a connection that may set them, "+
				"so every commit reaches disk", flush, binlog)
		case database.SQLite:
			// A pragma on every test connection, which is where the file is
			// written and so where the syncing would be.
			var synchronous int
			if err := db.QueryRowContext(ctx, `PRAGMA synchronous`).Scan(&synchronous); err != nil {
				t.Fatalf("read the synchronous pragma: %v", err)
			}
			if synchronous != 0 {
				t.Errorf("synchronous is %d, so every commit syncs the file", synchronous)
			}
		default:
			t.Fatalf("%s is not one of the four engines this pins", engine)
		}
	})
}
