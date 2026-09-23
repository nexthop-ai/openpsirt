// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationNoTxContext(upV020, downV020)
}

// The v0.1.0 release's schema changed into v0.2.0's, and the rows it holds
// moved with it.
//
// Every migration before this one is the one v0.1.0 shipped, unchanged, so a
// database that release built has applied exactly those and applies this
// next. A fresh install walks the same chain.
//
// It is registered without the library's transaction and opens its own,
// because SQLite's foreign keys have to be switched off before a transaction
// begins, and because the rows it moves are read back by name.
func upV020(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV020)
}

// downV020 puts back the tables and columns v0.1.0 had. What v0.2.0 recorded
// that v0.1.0 has nowhere to hold is dropped with the tables and columns that
// held it.
func downV020(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, downgradeV020)
}

// inV020 runs one direction in one transaction.
//
// On PostgreSQL and SQLite a failure leaves the schema as it was. On MySQL and
// MariaDB every data-definition statement commits as it runs, so a failure
// leaves part of it applied and the version unrecorded; a backup taken before
// is what recovers it.
//
// SQLite changes a table's shape by building a replacement and dropping the
// original, which is refused while foreign keys are enforced and a table
// points at it. The setting is ignored inside a transaction, so it is made
// before one begins, on the one connection SQLite is held to, and every
// reference is checked before the transaction commits.
func inV020(ctx context.Context, sqldb *sql.DB, run func(context.Context, bun.Tx) error) (err error) {
	engine := migrate.EngineFrom(ctx)
	db, err := database.Query(sqldb, engine)
	if err != nil {
		return err
	}
	if engine == database.SQLite {
		if _, err := sqldb.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return fmt.Errorf("suspend foreign keys: %w", err)
		}
		defer func() {
			if _, restore := sqldb.ExecContext(context.WithoutCancel(ctx), `PRAGMA foreign_keys = ON`); restore != nil && err == nil {
				err = fmt.Errorf("restore foreign keys: %w", restore)
			}
		}()
	}
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := run(ctx, tx); err != nil {
			return err
		}
		return foreignKeysHold(ctx, engine, tx)
	})
}

// foreignKeysHold checks every reference SQLite did not enforce while the
// migration ran.
func foreignKeysHold(ctx context.Context, engine database.Engine, tx bun.Tx) error {
	if engine != database.SQLite {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("check the references the migration kept: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		var table, parent string
		var row sql.NullInt64
		var fk int64
		if err := rows.Scan(&table, &row, &parent, &fk); err != nil {
			return fmt.Errorf("check the references the migration kept: %w", err)
		}
		return fmt.Errorf("a row of %s points at no row of %s", table, parent)
	}
	return rows.Err()
}
