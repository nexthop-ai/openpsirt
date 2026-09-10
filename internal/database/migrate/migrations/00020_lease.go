package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
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
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
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
	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// The primary key goes with the table and is not dropped separately.
func downLease(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `DROP TABLE "lease"`); err != nil {
		return fmt.Errorf("drop lease: %w", err)
	}
	return nil
}
