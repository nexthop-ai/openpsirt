// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationNoTxContext(upV030, downV030)
}

// The v0.2.0 release's schema changed into v0.3.0's, and the rows it holds
// moved with it.
//
// Every migration before this one is one a tagged release shipped, unchanged,
// so a database v0.2.0 built has applied exactly those and applies this next.
// A database v0.1.0 built applies migration 37 and then this. A fresh install
// walks the same chain.
//
// Run in one transaction of its own, the way migration 37 is, and for the same
// reasons: the rows it moves are read back by name, and on SQLite the
// references are checked before the transaction commits.
func upV030(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV030)
}

// downV030 puts back the schema v0.2.0 built. What v0.3.0 recorded that
// v0.2.0 has nowhere to hold is dropped with the columns that held it.
func downV030(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, downgradeV030)
}
