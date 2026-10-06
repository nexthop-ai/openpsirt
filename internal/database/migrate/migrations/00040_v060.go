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
	goose.AddMigrationNoTxContext(upV060, nil)
}

// The v0.5.0 release's schema changed into v0.6.0's.
//
// Run in one transaction of its own, the way
// migrations 37 to 39 are, and for the same reason: SQLite rebuilds the table
// it cannot alter, and its foreign keys are switched off before the
// transaction begins.
func upV060(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV060)
}

// upgradeV060 changes the schema v0.5.0 built into v0.6.0's.
//
// The v060 files beside this one hold v0.6.0's declaration of
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
//   - A group's role names its product by name, and a group may hold a role
//     across every product. Configuration is the only source of either and is
//     applied at every start, so the role mappings v0.5.0 holds are dropped
//     rather than carried. Mappings to admin and audit are left alone.
//   - A key's or a token's name is unique among those in force, so a
//     withdrawn name may be given again. Every credential v0.5.0 holds in
//     force keeps its name in force.
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
	if err := u.create(obligationV060(t), "exploited_fix"); err != nil {
		return err
	}
	if err := dropTables(ctx, tx.Tx, "group_role"); err != nil {
		return err
	}
	if err := u.create(groupRoleV060(t), "group_role", "group_role_all"); err != nil {
		return err
	}
	return u.liveNames()
}
