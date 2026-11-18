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
	goose.AddMigrationNoTxContext(upV0140, nil)
}

// The v0.13.0 release's schema changed into v0.14.0's.
//
// Run in one transaction of its own, the way migrations 45 to 47 are.
func upV0140(ctx context.Context, sqldb *sql.DB) error {
	return releaseUpgrade(ctx, sqldb, 48, upgradeV0140)
}

// upgradeV0140 changes the schema v0.13.0 built into v0.14.0's.
//
// The v0140 files beside this one hold v0.14.0's declaration of every table
// this changes.
//
//   - A finding's group index holds the run that opened it, and its run
//     indexes why it closed, so the trend and what each upload changed read
//     no table row.
//   - A build's own claims and received statements keep the status notes each
//     gives.
//   - A finding records the source package it was matched through, an issue
//     the files its CVE record lists, and a correction by source paths is
//     kept with what it answered and on which files.
//   - A component holds what the inventory says it is.
//   - A component holds the name its package identifier gives, folded and
//     indexed, which a statement is matched by beside its own name.
func upgradeV0140(ctx context.Context, tx bun.Tx) error {
	for _, step := range []func(context.Context, bun.Tx) error{
		findingIndexesV0140,
		statementNotesV0140,
		sourceCorrectionsV0140,
		componentDescriptionV0140,
		componentPackageV0140,
	} {
		if err := step(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
