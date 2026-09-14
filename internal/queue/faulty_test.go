package queue_test

import (
	"context"
	"testing"

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
		// What the other worker did while the first attempt was losing: it
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
	if _, err := q.Add(ctx, "ingest", "finishes"); err != nil {
		t.Fatal(err)
	}
	job, err := q.Claim(ctx, "worker", "ingest")
	if err != nil || job == nil {
		t.Fatalf("claiming: %v", err)
	}

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
