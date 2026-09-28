// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationNoTxContext(upV050, downV050)
}

// The v0.4.0 release's schema changed into v0.5.0's, and the rows it holds
// moved onto v0.5.0's rules.
//
// Run in one transaction of its own, the way migrations 37 and 38 are, and
// for the same reason: SQLite rebuilds the table it cannot alter, and its
// foreign keys are switched off before the transaction begins.
func upV050(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV050)
}

// downV050 puts back the schema v0.4.0 built, and the rows the way v0.4.0
// reads them.
func downV050(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, downgradeV050)
}

// upgradeV050 changes the schema v0.4.0 built into v0.5.0's and moves the rows.
//
// The v050 files beside this one hold v0.5.0's declaration of every table this
// changes.
//
//   - The administrative trail records who acted as a person or as the
//     deployment's startup configuration. Every row v0.4.0 wrote was a
//     person's, and keeps its person.
//   - Administration named in configuration is separated from administration
//     granted here. v0.4.0 wrote both into one column, so a name removed from
//     configuration left its administration standing. v0.5.0 reads the name
//     as a grant of its own, and the column holds only what was granted here
//     or derived from a group. A named administrator whose row says a group
//     derived it keeps that, because a group is what says so. Every other
//     named administrator's column is cleared: v0.4.0 kept nothing complete
//     that tells a grant made here apart from the one the name wrote, and
//     clearing it is the reading that ends with configuration deciding. The
//     administrative trail holds a grant made here that moved the column, and
//     none made while the name already had. They administer through the name
//     for as long as it stays in configuration.
func upgradeV050(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	if err := u.change(trailV050(t), change{table: "admin_change",
		add:   []added{{column: "actor", fill: "'person'"}},
		relax: []string{"by"}}); err != nil {
		return err
	}
	if _, err := tx.NewRaw(`UPDATE "person" SET "is_admin" = ?`+
		` WHERE "is_bootstrap" = ? AND "admin_derived" = ?`, false, true, false).
		Exec(ctx); err != nil {
		return fmt.Errorf("separate administration named in configuration: %w", err)
	}
	return nil
}

// downgradeV050 puts back what v0.4.0 reads.
//
// The name is written back into the administration column, which is where
// v0.4.0 reads it. A trail row configuration wrote has no person, which
// v0.4.0 has no place for, so it goes with the column that says who acted.
func downgradeV050(ctx context.Context, tx bun.Tx) error {
	if _, err := tx.NewRaw(`UPDATE "person" SET "is_admin" = ? WHERE "is_bootstrap" = ?`,
		true, true).Exec(ctx); err != nil {
		return fmt.Errorf("fold administration named in configuration back in: %w", err)
	}

	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	trail := narrowing{table: "admin_change",
		forget:  `DELETE FROM "admin_change" WHERE "actor" = 'configuration'`,
		columns: []string{"actor"}}
	if u.engine == database.SQLite {
		trail.require = []string{"by"}
		return u.narrow(trail)
	}
	if err := u.narrow(trail); err != nil {
		return err
	}
	if u.engine == database.Postgres {
		return u.run([]string{`ALTER TABLE "admin_change" ALTER COLUMN "by" SET NOT NULL`})
	}
	made, _, err := pick(trailV050(t), "admin_change")
	if err != nil {
		return err
	}
	items, err := declared(made)
	if err != nil {
		return err
	}
	def, err := items.column("by")
	if err != nil {
		return err
	}
	return u.run([]string{`ALTER TABLE "admin_change" MODIFY COLUMN ` + refusingNull(def)})
}
