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
func upgradeV070(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	if err := u.change(findingV070(t), change{table: "finding",
		add: []added{{column: "unaffected_by"}}}); err != nil {
		return err
	}
	return u.change(scanRunV070(t), change{table: "scan_run",
		add: []added{{column: "records_version"}}})
}
