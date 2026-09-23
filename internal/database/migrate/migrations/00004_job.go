// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upJob, downJob)
}

// Work waiting to be done.
//
// The queue lives in the database rather than in a broker because the
// alternatives do not fit: the mature Go queues are tied to one engine or need
// a separate service, and neither is acceptable for something an operator
// installs against whatever database they already run.
func upJob(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "job" (
			"id"           ` + t.id + `,
			"kind"         ` + t.name + ` NOT NULL,
			"reference"    ` + t.name + ` NOT NULL,
			"state"        ` + t.kind + ` NOT NULL,
			"attempts"     INTEGER NOT NULL,
			"max_attempts" INTEGER NOT NULL,
			"run_after"    ` + t.timestamp + ` NOT NULL,
			"claimed_by"   ` + t.name + ` NULL,
			"claimed_at"   ` + t.timestamp + ` NULL,
			"last_error"   ` + t.text + ` NULL,
			"created_at"   ` + t.timestamp + ` NOT NULL,
			"updated_at"   ` + t.timestamp + ` NOT NULL
		)` + t.suffix,

		// Claiming asks for the oldest runnable job of one kind, which is the
		// query on the path of every worker poll. Kind leads, because workers
		// of different sorts share this table and a worker that scanned rows
		// belonging to another would lock and skip them on every poll.
		`CREATE INDEX "job_runnable_idx" ON "job" ("kind", "state", "run_after", "id")`,

		// What an operator opens because the queue has gone wrong. It filters
		// on state and orders by when the row last moved, and the index above
		// leads with the kind, which this query does not name — so without
		// this it scans every job the deployment has ever run, and nothing
		// deletes a finished one.
		`CREATE INDEX "job_set_aside_idx" ON "job" ("state", "updated_at", "id")`,
	}

	return apply(ctx, tx, statements)
}

func downJob(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "job")
}
