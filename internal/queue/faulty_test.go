// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

func TestAClaimThatWasRolledBackIsNotReturned(t *testing.T) {
	// A commit refused for a reason worth retrying re-runs the whole closure.
	// The claim it had already made is gone, because the transaction that
	// made it was rolled back — so if the job it scanned survives into the
	// next attempt, a worker is handed a claim the database does not have and
	// runs work somebody else holds. On an ingest that looks like real change
	// rather than an error.
	//
	// The ordinary failure on a cluster, not an exotic one: a certification
	// failure arrives at COMMIT on a transaction whose every statement had
	// already succeeded.
	ctx := t.Context()

	var handle *database.DB
	var owner *dbtest.Race
	handle, owner = dbtest.Racing(t, func() {
		// The other worker's own act while the first attempt was losing: it
		// finished the job, so there is nothing left for the retry to claim.
		if _, err := handle.ExecContext(context.WithoutCancel(ctx),
			`UPDATE "job" SET "state" = 'done'`); err != nil {
			t.Errorf("marking the job done between attempts: %v", err)
		}
	})

	q := queue.New(handle, queue.DefaultOptions())
	if _, err := q.Add(ctx, "ingest", "the-only-job"); err != nil {
		t.Fatal(err)
	}

	owner.Arm(1)
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if job != nil {
		t.Errorf("a claim that was rolled back came back as job %d for %q — "+
			"the work is somebody else's and this worker would run it too",
			job.ID, "worker")
	}
}

func TestACommitThatLosesARaceIsTriedAgain(t *testing.T) {
	// The other half, and the one that must not regress: losing a race is not
	// a failure, it is a reason to go again. A claim that loses one commit
	// still hands out the job.
	ctx := t.Context()
	handle, owner := dbtest.Racing(t, nil)

	q := queue.New(handle, queue.DefaultOptions())
	if _, err := q.Add(ctx, "ingest", "the-only-job"); err != nil {
		t.Fatal(err)
	}

	owner.Arm(1)
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil {
		t.Fatalf("claiming: %v", err)
	}
	if job == nil {
		t.Fatal("a claim that lost one commit gave up rather than going again")
	}
	if job.Reference != "the-only-job" {
		t.Errorf("claimed %q", job.Reference)
	}
}

func TestFinishingWorkSurvivesACommitThatLosesARace(t *testing.T) {
	// A cluster certifies at COMMIT, so a write whose statements all succeeded
	// can still be rolled back under it. Reported up rather than retried, that
	// turns a job which finished into a job the caller records as failed and
	// the queue hands out again — the work runs twice, which on an ingest
	// looks like real change.
	ctx := t.Context()
	handle, owner := dbtest.Racing(t, nil)

	q := queue.New(handle, queue.DefaultOptions())
	job := claimed(t, q, "ingest", "finishes", "worker")

	owner.Arm(1)
	if err := q.Succeed(ctx, job.ID, "worker"); err != nil {
		t.Fatalf("finishing work lost one commit and gave up: %v", err)
	}
	if owner.Unspent() != 0 {
		t.Fatalf("finishing work committed nothing this could refuse, so it writes " +
			"outside a transaction and a refused commit cannot be retried at all")
	}

	var state string
	if err := handle.QueryRowContext(ctx,
		`SELECT "state" FROM "job" WHERE "id" = ?`, job.ID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != string(queue.Done) {
		t.Errorf("the job is %q rather than %q after finishing", state, queue.Done)
	}
}

// Work that succeeded and whose ending could not be recorded reports the
// failure to record, rather than success.
func TestWorkWhoseEndingCannotBeRecordedSaysSo(t *testing.T) {
	ctx := t.Context()
	handle, owner := dbtest.Racing(t, nil)
	q := queue.New(handle, queue.DefaultOptions())
	if _, err := q.Add(ctx, "ingest", "unrecorded"); err != nil {
		t.Fatal(err)
	}
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil || job == nil {
		t.Fatalf("claiming: %v", err)
	}
	owner.Arm(database.Attempts)
	ending := q.Settle(ctx, job, "worker", "upload", nil, nil, nil, nil)
	if ending.Err == nil || ending.HandedOver {
		t.Errorf("work whose success could not be recorded settled as %+v", ending)
	}
}

// Finishing work whose row already reads finished, on a retry, is finished:
// a commit that went through and whose answer was lost is not a lost claim.
func TestFinishingWorkAlreadyRecordedAsFinishedIsNotALostClaim(t *testing.T) {
	ctx := t.Context()
	var handle *database.DB
	var owner *dbtest.Race
	handle, owner = dbtest.Racing(t, func() {
		if _, err := handle.ExecContext(context.WithoutCancel(ctx),
			`UPDATE "job" SET "state" = 'done', "claimed_by" = NULL`); err != nil {
			t.Errorf("recording the job done between attempts: %v", err)
		}
	})
	q := queue.New(handle, queue.DefaultOptions())
	if _, err := q.Add(ctx, "ingest", "answer-lost"); err != nil {
		t.Fatal(err)
	}
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil || job == nil {
		t.Fatalf("claiming: %v", err)
	}
	owner.Arm(1)
	if err := q.Succeed(ctx, job.ID, "worker"); err != nil {
		t.Errorf("finishing work that reads finished answered %v", err)
	}
}

func TestQueueingWorkSurvivesACommitThatLosesARace(t *testing.T) {
	// The same at the other end: a refused commit on the insert meant the work
	// was never queued, and the caller was told so.
	ctx := t.Context()
	handle, owner := dbtest.Racing(t, nil)

	q := queue.New(handle, queue.DefaultOptions())
	owner.Arm(1)
	job, err := q.Add(ctx, "ingest", "queued-despite-a-lost-race")
	if err != nil {
		t.Fatalf("queueing work lost one commit and gave up: %v", err)
	}
	if job == nil {
		t.Fatal("nothing was queued")
	}
	if owner.Unspent() != 0 {
		t.Fatalf("queueing work committed nothing this could refuse, so it writes " +
			"outside a transaction and a refused commit cannot be retried at all")
	}

	var queued int
	if err := handle.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM "job" WHERE "reference" = ?`, "queued-despite-a-lost-race").
		Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if queued != 1 {
		t.Errorf("%d rows were queued, want exactly one", queued)
	}
}

// A job that becomes claimable while a claim waits to go again is claimed on
// the retry. The moment is read on each attempt: one read before the first
// describes a clock that has since moved, and the stale claim the retry could
// take over is still fresh to it.
func TestAClaimTakenAgainReadsTheMomentAgain(t *testing.T) {
	ctx := t.Context()
	opts := queue.DefaultOptions()
	now := time.Now().UTC()
	handle, owner := dbtest.Racing(t, func() { now = now.Add(2 * time.Minute) })
	q := queue.New(handle, opts)
	queue.SetClock(q, func() time.Time { return now })
	if _, err := q.Add(ctx, "ingest", "held-by-one-that-died"); err != nil {
		t.Fatal(err)
	}
	if job, err := q.Claim(ctx, "dead", "ingest"); err != nil || job == nil {
		t.Fatalf("first claim: %v", err)
	}
	// A minute short of stale when the claim begins, and past it once the
	// lost commit has been waited out.
	now = now.Add(opts.ClaimTimeout - time.Minute)

	owner.Arm(1)
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil {
		t.Fatal(err)
	}
	if owner.Unspent() != 0 {
		t.Fatal("no commit was lost, so nothing was taken again")
	}
	if job == nil {
		t.Error("a claim gone stale while the claim waited to go again was left with the worker that died")
	}
}

// A lease taken again after a lost commit runs from the moment of the attempt
// that commits, and its row is made inside the transaction that is retried: a
// row that went away while the commit was lost is made again.
func TestALeaseTakenAgainIsMadeAndTimedByTheAttemptThatCommits(t *testing.T) {
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	var handle *database.DB
	var owner *dbtest.Race
	handle, owner = dbtest.Racing(t, func() {
		now = now.Add(time.Hour)
		if _, err := handle.ExecContext(context.WithoutCancel(ctx), `DELETE FROM "lease"`); err != nil {
			t.Errorf("take the lease's row away between attempts: %v", err)
		}
	})
	leases := queue.NewLeases(handle.DB)
	queue.SetLeaseClock(leases, func() time.Time { return now })

	owner.Arm(1)
	mine, err := leases.Take(ctx, "sweeping", "me", time.Minute)
	if err != nil || !mine {
		t.Fatalf("a take that lost one commit answered %v %v", mine, err)
	}
	if owner.Unspent() != 0 {
		t.Fatal("no commit was lost, so nothing was taken again")
	}
	var until time.Time
	if err := handle.QueryRowContext(ctx, `SELECT "held_until" FROM "lease" WHERE "name" = 'sweeping'`).
		Scan(&until); err != nil {
		t.Fatal(err)
	}
	if want := now.Add(time.Minute); !until.Equal(want) {
		t.Errorf("the lease is held until %s, want %s from the attempt that committed", until, want)
	}
}

// A take that fails while a lease is awaited is a turn missed, not the end of
// the wait: work that has to happen is not dropped for one failure.
func TestWaitingForALeaseOutlastsATakeThatFails(t *testing.T) {
	ctx, stop := context.WithTimeout(t.Context(), 30*time.Second)
	defer stop()
	handle, owner := dbtest.Racing(t, nil)
	leases := queue.NewLeases(handle.DB)
	// Every attempt of the first take loses, so it fails outright, and the
	// second take loses once and commits.
	owner.Arm(database.Attempts + 1)
	if err := leases.Await(ctx, "rewriting", "me", time.Minute, 5*time.Millisecond); err != nil {
		t.Errorf("a wait whose first take failed gave up: %v", err)
	}
	if owner.Unspent() != 0 {
		t.Errorf("%d commits never happened, so no take failed", owner.Unspent())
	}
}
