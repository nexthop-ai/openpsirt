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
	goose.AddMigrationNoTxContext(upV0100, nil)
}

// The v0.9.0 release's schema changed into v0.10.0's.
//
// Run in one transaction of its own, the way migration 42 is.
func upV0100(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV0100)
}

// upgradeV0100 changes the schema v0.9.0 built into v0.10.0's.
//
// The v0100 files beside this one hold v0.10.0's declaration of every table
// this changes.
//
//   - A build's findings are indexed by the run that opened them and by the
//     run that closed them, each with what counting a run's changes reads.
func upgradeV0100(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	return u.index(findingV0100(t), "finding", "finding_opened_run_idx", "finding_closed_run_idx")
}
