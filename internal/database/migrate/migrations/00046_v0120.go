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
	goose.AddMigrationNoTxContext(upV0120, nil)
}

// The v0.11.0 release's schema changed into v0.12.0's.
//
// Run in one transaction of its own, the way migrations 44 and 45 are.
func upV0120(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV0120)
}

// upgradeV0120 changes the schema v0.11.0 built into v0.12.0's.
//
// The v0120 files beside this one hold v0.12.0's declaration of every table
// this changes.
//
//   - An issue records when it was published and last modified, as a public
//     vulnerability database answers, and when that database was last asked.
//   - A scan run records the replaced inventory it checked, where it is the
//     check a replaced branch inventory owes.
func upgradeV0120(ctx context.Context, tx bun.Tx) error {
	for _, step := range []func(context.Context, bun.Tx) error{issueDatesV0120, checkedScanV0120} {
		if err := step(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
