package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// claimableID finds the oldest job this worker may take, and holds it against
// every other worker until the surrounding transaction ends.
//
// This is about throughput, not correctness. Correctness comes from the
// conditional update in Claim, which only succeeds if the job is still
// claimable and works the same on every engine. Without that, an engine whose
// locking was got wrong would hand the same work out twice — and on an ingest
// that looks like real change rather than an error.
//
// What locking adds is that workers do not queue behind one another on the
// same row. Without it, several workers all select the oldest job, one wins
// and the rest did their round trip for nothing; with it, each takes a
// different job. The query cannot be written portably, so each engine is
// spelled out rather than hidden behind an abstraction that would make it look
// portable when it is not.
func claimableID(ctx context.Context, tx bun.Tx, engine database.Engine, kind string, now, staleBefore time.Time) (int64, error) {
	// Filtered by kind. Workers of different sorts share one queue, and a
	// worker that took work meant for another would do the wrong thing to it
	// and then mark it done — the reference means something different to each
	// of them, so the mistake does not even fail.
	// The attempts ceiling is charged on the reclaim arm as well as by Fail.
	// A worker that dies reports nothing, so the only record of the attempt is
	// the count the claim itself incremented — and without the ceiling here,
	// a job whose worker is killed every time is reclaimed for ever and the
	// state that says so is never reached.
	const base = `SELECT id FROM job
		 WHERE kind = ?
		   AND ((state = ? AND run_after <= ?)
		    OR  (state = ? AND claimed_at < ? AND attempts < max_attempts))
		 ORDER BY id
		 LIMIT 1`

	query := base
	switch engine {
	case database.Postgres, database.MySQL, database.MariaDB:
		// FOR UPDATE takes the row. SKIP LOCKED is what makes several workers
		// useful: without it they queue behind each other on the same row and
		// the pool is a single worker with extra steps.
		query += " FOR UPDATE SKIP LOCKED"

	case database.SQLite:
		// No row locking, and none needed. SQLite is used by one process with
		// a single connection, so the surrounding transaction already excludes
		// every other claim.

	default:
		return 0, fmt.Errorf("no claim strategy for %s", engine)
	}

	var id int64
	err := tx.NewRaw(query, kind, Pending, now, Running, staleBefore).Scan(ctx, &id)
	if err != nil {
		if database.IsNoRows(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("find claimable job: %w", err)
	}
	return id, nil
}
