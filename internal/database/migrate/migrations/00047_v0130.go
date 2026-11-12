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
	goose.AddMigrationNoTxContext(upV0130, nil)
}

// The v0.12.0 release's schema changed into v0.13.0's.
//
// Run in one transaction of its own, the way migrations 44 to 46 are.
func upV0130(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV0130)
}

// upgradeV0130 changes the schema v0.12.0 built into v0.13.0's.
//
// The v0130 files beside this one hold v0.13.0's declaration of every table
// this changes.
//
//   - An issue an advisory covers is one row per stretch it was covered for,
//     unique among the stretches still open, where it was one row revived.
//   - A release an advisory marks affected is one row per stretch it was
//     marked for, unique among the stretches still open, where it was one row
//     revived.
//   - A graph node holds the name and version its build stated for the
//     component, which the shared component row holds as the first report of
//     it stated them.
//   - A received VEX statement holds when its publisher made it and which
//     newer statement of theirs set it aside, and only the newest of a
//     publisher's statements about one subject stands.
//   - A decision occurrence records who withdrew it, where somebody did.
func upgradeV0130(ctx context.Context, tx bun.Tx) error {
	for _, step := range []func(context.Context, bun.Tx) error{advisoryCoverLiveV0130,
		advisoryOverrideLiveV0130, graphNodeStatedV0130, receivedStatementTimedV0130,
		receivedStatementNewestV0130, decisionEndedByV0130} {
		if err := step(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
