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
	goose.AddMigrationNoTxContext(upV080, nil)
}

// The v0.7.0 release's schema changed into v0.8.0's.
//
// Run in one transaction of its own, the way migrations 40 and 41 are.
func upV080(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV080)
}

// upgradeV080 changes the schema v0.7.0 built into v0.8.0's.
//
// The v080 files beside this one hold v0.8.0's declaration of every table
// this changes.
//
//   - What is open in a build is indexed with its deadline, and the grouping
//     index carries when a finding opened and why it closed.
//   - Decisions are indexed by state, with their claim and with their
//     product.
//   - On PostgreSQL, the finding table is vacuumed after a fiftieth of it
//     changes and analyzed after a hundredth, rather than a fifth and a
//     tenth.
func upgradeV080(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	if err := u.index(findingV080(t), "finding",
		"finding_open_idx", "finding_group_idx"); err != nil {
		return err
	}
	if err := u.index(decisionV080(t), "decision",
		"decision_state_claim_idx", "decision_state_product_idx"); err != nil {
		return err
	}
	if u.engine != database.Postgres {
		return nil
	}
	return u.run(findingVacuumV080)
}

// findingVacuumV080 is when PostgreSQL vacuums and analyzes the finding table.
//
// An index-only scan reads the table for every row on a page the visibility
// map does not mark all-visible, and only a vacuum marks one. A nightly scan
// rewrites tens of thousands of findings, below the fifth of the table the
// server's defaults wait for, so the pages it touched stay unmarked until the
// table has changed by that much. Measured over 375,843 findings with 46,980
// rewritten: at the defaults no vacuum ran, and the package-kind count read
// the table 413,331 times and took 246 ms; at a fiftieth a vacuum ran within
// the minute, and the count read the table not at all and took 64 ms.
var findingVacuumV080 = []string{
	`ALTER TABLE "finding" SET (
		"autovacuum_vacuum_scale_factor" = 0.02,
		"autovacuum_vacuum_insert_scale_factor" = 0.02,
		"autovacuum_analyze_scale_factor" = 0.01)`,
}
