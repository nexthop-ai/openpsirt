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
//   - A product records whether its security documents are served to anybody.
//   - A claim records whom a statement published from it holds for.
//   - The security documents served to anybody are kept, one row per
//     document, holding the revision a reader is handed now.
func upgradeV0100(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	if err := u.index(findingV0100(t), "finding", "finding_opened_run_idx", "finding_closed_run_idx"); err != nil {
		return err
	}
	for _, step := range []func(context.Context, bun.Tx) error{
		productPublishesV0100, claimScopeV0100, createPublishedDocumentV0100,
	} {
		if err := step(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
