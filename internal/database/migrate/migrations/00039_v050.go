// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"
)

func init() {
	goose.AddMigrationNoTxContext(upV050, downV050)
}

// The v0.4.0 release's rows moved onto v0.5.0's rules. The schema does not
// change.
//
// Run in one transaction of its own, the way migrations 37 and 38 are.
func upV050(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV050)
}

// downV050 puts the rows back the way v0.4.0 reads them.
func downV050(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, downgradeV050)
}

// upgradeV050 separates administration named in configuration from
// administration granted here.
//
// v0.4.0 wrote both into one column, so a name removed from configuration left
// its administration standing. v0.5.0 reads the name as a grant of its own,
// and the column holds only what was granted here or derived from a group. A
// named administrator whose row says a group derived it keeps that, because a
// group is what says so. Every other named administrator's column is cleared:
// v0.4.0 kept nothing that tells a grant made here apart from the one the name
// wrote, and clearing it is the reading that ends with configuration deciding.
// They administer through the name for as long as it stays in configuration.
func upgradeV050(ctx context.Context, tx bun.Tx) error {
	if _, err := tx.NewRaw(`UPDATE "person" SET "is_admin" = ?`+
		` WHERE "is_bootstrap" = ? AND "admin_derived" = ?`, false, true, false).
		Exec(ctx); err != nil {
		return fmt.Errorf("separate administration named in configuration: %w", err)
	}
	return nil
}

// downgradeV050 writes the name back into the column, which is where v0.4.0
// reads it.
func downgradeV050(ctx context.Context, tx bun.Tx) error {
	if _, err := tx.NewRaw(`UPDATE "person" SET "is_admin" = ? WHERE "is_bootstrap" = ?`,
		true, true).Exec(ctx); err != nil {
		return fmt.Errorf("fold administration named in configuration back in: %w", err)
	}
	return nil
}
