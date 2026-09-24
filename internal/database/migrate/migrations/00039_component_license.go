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
	goose.AddMigrationNoTxContext(upComponentLicense, downComponentLicense)
}

// The license an inventory declares for a component.
//
// One column, of the width a producer's own text has, empty on every row
// written before it. Nothing fills those in here: what a component is licensed
// under is read from an inventory, and the next scan of a build that ships it
// writes it onto the row, as a supplier is.
func upComponentLicense(ctx context.Context, sqldb *sql.DB) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	return componentLicense(ctx, sqldb,
		`ALTER TABLE "component" ADD COLUMN "license" `+t.free+` NULL`)
}

// downComponentLicense takes the column away, and what it held with it.
func downComponentLicense(ctx context.Context, sqldb *sql.DB) error {
	return componentLicense(ctx, sqldb, `ALTER TABLE "component" DROP COLUMN "license"`)
}

func componentLicense(ctx context.Context, sqldb *sql.DB, statement string) error {
	db, err := database.Query(sqldb, migrate.EngineFrom(ctx))
	if err != nil {
		return err
	}
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%s: %w", firstLine(statement), err)
		}
		return nil
	})
}
