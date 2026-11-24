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
	goose.AddMigrationNoTxContext(upV0150, nil)
}

// The v0.14.0 release's schema changed into v0.15.0's.
//
// Run in one transaction of its own, the way migrations 47 and 48 are.
func upV0150(ctx context.Context, sqldb *sql.DB) error {
	return releaseUpgrade(ctx, sqldb, 49, upgradeV0150)
}

// upgradeV0150 changes the schema v0.14.0 built into v0.15.0's.
//
// The v0150 files beside this one hold v0.15.0's declaration of every table
// this changes.
//
//   - A scan run records whether it recorded the source package each finding
//     it applied was matched through.
func upgradeV0150(ctx context.Context, tx bun.Tx) error {
	for _, step := range []func(context.Context, bun.Tx) error{
		scanRunSourcesV0150,
	} {
		if err := step(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
