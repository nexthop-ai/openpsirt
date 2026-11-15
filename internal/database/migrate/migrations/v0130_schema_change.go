// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"
)

// schemaChangeV0130 is v0.13.0's declaration of the record an upgrade keeps
// while it changes the schema.
func schemaChangeV0130(t *columnTypes) []string {
	return []string{
		// A row for each upgrade that began changing the schema and has not
		// ended with it whole. An instance serving the database pauses while
		// one stands, as it does while the schema change lock is held. The
		// lock goes with its session; this outlives an upgrade that fails
		// part way on an engine whose schema changes each commit alone, so
		// nothing serves the part-changed schema until an upgrade succeeds or
		// the backup is restored. A row names the version its upgrade was
		// reaching, and stops counting once the version applied reaches it,
		// so one a process left after its last migration pauses nobody.
		`CREATE TABLE "schema_change" (
			"id"             ` + t.id + `,
			"started_at"     ` + t.timestamp + ` NOT NULL,
			"started_by"     ` + t.name + ` NOT NULL,
			"target_version" BIGINT NOT NULL
		)` + t.suffix,
	}
}

// schemaChangeMadeV0130 makes the record of upgrades changing the schema.
// Stepped over where it is already there.
func schemaChangeMadeV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasColumn("schema_change", "id"); err != nil || present {
		return err
	}
	return u.create(schemaChangeV0130(u.t), "schema_change")
}

// changeRecorded writes, in a release's upgrade transaction, the record of
// the change to version, where the database has the table for it. It commits
// with the schema and rolls back with it, so a process killed after the
// commit and before the migration library records the version leaves a
// record that keeps every serving instance paused; the upgrade that records
// the version removes it.
func changeRecorded(ctx context.Context, tx bun.Tx, version int64) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if present, err := u.hasTable("schema_change"); err != nil || !present {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO "schema_change" ("started_at", "started_by", "target_version")
		VALUES (?, ?, ?)`, time.Now().UTC(), fmt.Sprintf("the migration to version %d", version), version); err != nil {
		return fmt.Errorf("record the schema change: %w", err)
	}
	return nil
}
