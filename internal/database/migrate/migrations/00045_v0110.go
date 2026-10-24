// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"
)

func init() {
	goose.AddMigrationNoTxContext(upV0110, nil)
}

// The v0.10.0 release's schema changed into v0.11.0's.
//
// Run in one transaction of its own, the way migration 42 is.
func upV0110(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV0110)
}

// upgradeV0110 changes the schema v0.10.0 built into v0.11.0's.
//
// The v0110 files beside this one hold v0.11.0's declaration of every table
// this changes.
//
//   - An issue records what sort of issue it is: a published vulnerability, a
//     flaw minted here, or an analyzer's rule.
//   - The finding indexes a read answers from without the table carry the
//     finding's kind.
func upgradeV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if err := u.index(findingV0110(u.t), "finding",
		"finding_group_idx", "finding_opened_run_idx", "finding_closed_run_idx"); err != nil {
		return err
	}
	for _, step := range []func(context.Context, bun.Tx) error{
		issueKindV0110,
	} {
		if err := step(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
