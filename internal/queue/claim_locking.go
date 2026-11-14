// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// staleClaim is a job held by a worker that has stopped reporting: running,
// claimed before staleBefore. The one spelling of staleness, which reclaiming,
// counting the backlog and burying all build on.
const staleClaim = `"state" = ? AND "claimed_at" < ?`

// reclaimable is a stale claim with attempts left, which any worker may take.
func reclaimable(staleBefore time.Time) (string, []any) {
	return `(` + staleClaim + ` AND "attempts" < "max_attempts")`, []any{Running, staleBefore}
}

// claimable is a job a worker may take at now: waiting and due, or a stale
// claim with attempts left. The select choosing a job and the update taking it
// both ask it, so the update only succeeds while the job still is.
func claimable(now, staleBefore time.Time) (string, []any) {
	arm, args := reclaimable(staleBefore)
	return `(("state" = ? AND "run_after" <= ?) OR ` + arm + `)`, append([]any{Pending, now}, args...)
}

// claimableID finds the oldest job this worker may take, and holds it against
// every other worker until the surrounding transaction ends.
//
// This is about throughput, not correctness. Correctness comes from the
// conditional update in Claim, which only succeeds if the job is still
// claimable and works the same on every engine. Without that, an engine whose
// locking was got wrong would hand the same work out twice — and on an ingest
// that looks like real change rather than an error.
//
// That claim is demonstrated rather than asserted: locking is what the caller
// passes, and the exclusivity test runs a second time with it off, on every
// engine. A property the whole design rests on is one somebody should be able
// to watch hold without it.
//
// Locking adds that workers do not queue behind one another on the
// same row. Without it, several workers all select the oldest job, one wins
// and the rest did their round trip for nothing; with it, each takes a
// different job. The query cannot be written portably, so each engine is
// spelled out rather than hidden behind an abstraction that would make it look
// portable when it is not.
func claimableID(ctx context.Context, tx bun.Tx, engine database.Engine, locking bool, kind string, now, staleBefore time.Time) (int64, error) {
	// Filtered by kind. Workers of different sorts share one queue, and a
	// worker that took work meant for another would do the wrong thing to it
	// and then mark it done — the reference means something different to each
	// of them, so the mistake does not even fail.
	// The attempts ceiling is charged on the reclaim arm as well as by Fail.
	// A worker that dies reports nothing, so the only record of the attempt is
	// the count the claim itself incremented — and without the ceiling here,
	// a job whose worker is killed every time is reclaimed for ever and the
	// state that says so is never reached.
	arm, armArgs := claimable(now, staleBefore)
	query := `SELECT "id" FROM "job" WHERE "kind" = ? AND ` + arm + ` ORDER BY "id" LIMIT 1`
	switch engine {
	case database.Postgres, database.MySQL, database.MariaDB:
		// FOR UPDATE takes the row. SKIP LOCKED is what makes several workers
		// useful: without it they queue behind each other on the same row and
		// the pool is a single worker with extra steps.
		if locking {
			query += " FOR UPDATE SKIP LOCKED"
		}

	case database.SQLite:
		// No row locking, and none needed. Every SQLite transaction takes the
		// file's write lock as it begins, so the surrounding transaction
		// already excludes every other claim.

	default:
		return 0, fmt.Errorf("no claim strategy for %s", engine)
	}

	var id int64
	err := tx.NewRaw(query, append([]any{kind}, armArgs...)...).Scan(ctx, &id)
	if err != nil {
		if database.IsNoRows(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("find claimable job: %w", err)
	}
	return id, nil
}
