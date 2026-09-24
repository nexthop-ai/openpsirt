// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
)

func init() {
	goose.AddMigrationContext(upLease, downLease)
}

// Which replica is doing a piece of recurring work.
//
// Every replica runs the same binary with no leader and no process-local state
// that decides anything, so work that should happen once happens on all of
// them unless something in the database says otherwise. The job queue answers
// that for discrete work; this answers it for the recurring passes, which have
// no work item to claim.
//
// A row per named piece of work, taken by a conditional update and let go when
// it lapses — the same mechanism the queue claims a job with, and portable for
// the same reason: the statement repeats the conditions that made the lease
// available, so a second replica's update matches nothing.
func upLease(ctx context.Context, tx *sql.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}

	statements := []string{
		`CREATE TABLE "lease" (
			"name"       ` + t.name + ` NOT NULL,
			-- Which replica holds it, and until when. Null once nobody does.
			--
			-- A lease that lapses rather than one that is only ever handed
			-- back: a replica that dies holding one would otherwise stop the
			-- work happening at all, which is the failure the whole
			-- arrangement exists to avoid.
			"held_by"    ` + t.name + ` NULL,
			"held_until" ` + t.timestamp + ` NULL,
			CONSTRAINT "lease_pk" PRIMARY KEY ("name")
		)` + t.suffix,
	}
	return apply(ctx, tx, statements)
}

// The primary key goes with the table and is not dropped separately.
func downLease(ctx context.Context, tx *sql.Tx) error {
	return dropTables(ctx, tx, "lease")
}
