// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// schemaChangeV0130 is v0.13.0's declaration of the record an upgrade keeps
// while it changes the schema.
func schemaChangeV0130(t *columnTypes) []string {
	return []string{
		// A row for each upgrade that began changing the schema and has not
		// ended with it whole. An instance serving the database pauses while
		// one stands, as it does while the migration lease is held to change
		// the schema. The lease lapses once its holder is gone; this outlives
		// an upgrade that fails part way on an engine whose schema changes
		// each commit alone, so nothing serves the part-changed schema until
		// an upgrade succeeds or the backup is restored. A row names the
		// version its upgrade was reaching, and stops counting once the
		// version applied reaches it, so one a process left after its last
		// migration pauses nobody.
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
	if present, err := u.hasTable("schema_change"); err != nil || present {
		return err
	}
	return u.create(schemaChangeV0130(u.t), "schema_change")
}
