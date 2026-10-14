// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationNoTxContext(upV090, nil)
}

// The v0.8.0 release's schema changed into v0.9.0's.
//
// Run in one transaction of its own, the way migrations 40 to 42 are.
func upV090(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV090)
}

// upgradeV090 changes the schema v0.8.0 built into v0.9.0's.
//
// The v090 files beside this one hold v0.9.0's declaration of every table
// this creates, and the rows it moves.
//
//   - The version each build states for a container image is kept per
//     build, in a table of its own.
//   - A container image is identified by its name: the components v0.8.0
//     made per version of one are merged into one, and everything pointing at
//     them is pointed at it.
func upgradeV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	if err := u.create(imageVersionV090(t), "image_version"); err != nil {
		return err
	}
	return mergeImagesV090(ctx, tx)
}
