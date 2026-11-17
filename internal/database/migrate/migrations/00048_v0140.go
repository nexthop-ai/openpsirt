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
//   - A finding is indexed by its build and every column a trend reduces one
//     build's findings to moments by.
func upgradeV0140(ctx context.Context, tx bun.Tx) error {
	for _, step := range []func(context.Context, bun.Tx) error{findingMomentV0140} {
		if err := step(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
