// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationNoTxContext(upV070, nil)
}

// The v0.6.0 release's schema changed into v0.7.0's.
//
// Run in one transaction of its own, the way migrations 37 to 40 are.
func upV070(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV070)
}

// upgradeV070 changes the schema v0.6.0 built into v0.7.0's.
//
// The v070 files beside this one hold v0.7.0's declaration of
// every table this changes.
//
//   - A finding closed because a CVE record states its version is unaffected
//     keeps the lines that said so. No finding v0.6.0 holds was closed that
//     way.
//   - A run records which CVE record snapshot it read. No run v0.6.0 holds
//     read one.
//   - A finding names the supplier's statement that answers it. No finding
//     v0.6.0 holds is answered by one.
//   - A statement keeps the product its component ships inside, and what it
//     names its supplier's product as. A statement v0.6.0 holds kept neither,
//     and closes nothing until it is read again.
//   - Every supplier read from its directory is read again from its window,
//     so its advisories are read with the product they place. A claim an
//     advisory read again repeats keeps its row, whatever else the product
//     now keeps from it, and raises no notice.
//   - A build's claim keeps the product its target ships inside, and the
//     published statement it was taken from. No claim v0.6.0 holds kept
//     either, and each applies across the build until a scan restates it
//     with its product.
//   - A finding names the build's claim covering it, whatever the claim
//     says. Every finding v0.6.0 holds names none until the next run.
//   - A VEX document that went out records which kind it was, and revisions
//     are numbered per kind. Every one v0.6.0 recorded was this deployment's
//     own.
func upgradeV070(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	if err := u.change(findingV070(t), change{table: "finding",
		add: []added{{column: "unaffected_by"}, {column: "stated_by"},
			{column: "claimed_by"}}}); err != nil {
		return err
	}
	if err := u.change(suppressionV070(t), change{table: "suppression",
		add: []added{{column: "within_purl"}, {column: "within_name"},
			{column: "within_version"}, {column: "stated_by"}}}); err != nil {
		return err
	}
	if err := u.change(vexStatementsV070(t), change{table: "vex_statement",
		add: []added{{column: "within_purl"}, {column: "within"}, {column: "within_about"},
			{column: "placement"}}}); err != nil {
		return err
	}
	if err := u.run([]string{
		`UPDATE "advisory_source" SET "caught_up_to" = NULL, "caught_up_mark" = NULL`,
	}); err != nil {
		return err
	}
	if err := u.change(vexIssuanceV070(t), change{table: "vex_issuance",
		add:         []added{{column: "kind", fill: "'ours'"}},
		constraints: []string{"vex_issuance_once_per_kind"}}); err != nil {
		return err
	}
	// A rebuilt SQLite table is made without it. Dropped after the new rule
	// exists, because MySQL and MariaDB refuse to drop the index a foreign key
	// is served by, and the build is served by either.
	if u.engine != database.SQLite {
		if err := u.dropUnique("vex_issuance", "vex_issuance_once"); err != nil {
			return err
		}
	}
	return u.change(scanRunV070(t), change{table: "scan_run",
		add: []added{{column: "records_version"}}})
}
