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
	goose.AddMigrationNoTxContext(upV060, downV060)
}

// The v0.5.0 release's schema changed into the untagged release's.
//
// Edited until a tag ships it. Run in one transaction of its own, the way
// migrations 37 to 39 are, and for the same reason: SQLite rebuilds the table
// it cannot alter, and its foreign keys are switched off before the
// transaction begins.
func upV060(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV060)
}

// downV060 puts back the schema v0.5.0 built.
func downV060(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, downgradeV060)
}

// upgradeV060 changes the schema v0.5.0 built into the untagged release's.
//
// The v060 files beside this one hold the untagged release's declaration of
// every table this changes.
//
//   - A window may count from the first notice naming another window. Every
//     window v0.5.0 holds counts from the moment the attack became known,
//     which is a window naming none.
//   - A window may count from the release of a fix a record names. Every
//     window v0.5.0 holds counts from no fix.
//   - A notice records the reference its recipient gave it, what it said
//     about malice, and the places it named. Every notice v0.5.0 holds says
//     none of them.
//   - A record names the releases carrying its fix. No record v0.5.0 holds
//     names any.
func upgradeV060(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	if err := u.change(obligationV060(t), change{table: "obligation_window",
		add:         []added{{column: "from_window_id"}, {column: "from_fix", fill: "FALSE"}},
		constraints: []string{"obligation_window_from_fk"}}); err != nil {
		return err
	}
	if err := u.change(obligationV060(t), change{table: "told_outside",
		add: []added{{column: "reference"}, {column: "suspected_malicious"}}}); err != nil {
		return err
	}
	if err := u.create(obligationV060(t), "told_place"); err != nil {
		return err
	}
	return u.create(obligationV060(t), "exploited_fix")
}

// downgradeV060 puts back what v0.5.0 reads.
//
// The places a notice named and the releases a record named as carrying its
// fix go with their tables, and a notice's reference and what it said about
// malice with their columns. A window counting from another's notice or from
// a fix counts from the moment the attack became known again, which is the
// only start v0.5.0 has.
func downgradeV060(ctx context.Context, tx bun.Tx) error {
	if err := dropTables(ctx, tx.Tx, "told_place", "exploited_fix"); err != nil {
		return err
	}
	if err := apply(ctx, tx.Tx, []string{
		`ALTER TABLE "told_outside" DROP COLUMN "reference"`,
		`ALTER TABLE "told_outside" DROP COLUMN "suspected_malicious"`,
	}); err != nil {
		return err
	}
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	return u.narrow(narrowing{table: "obligation_window",
		keys: []string{"obligation_window_from_fk"}, columns: []string{"from_window_id", "from_fix"}})
}
