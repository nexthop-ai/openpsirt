package queue_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// quiet is a logger for the paths that report a renewal that did not land.
// Nothing here asserts on the log; what it says is checked by reading it.
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func each(t *testing.T, opts queue.Options, fn func(t *testing.T, db *database.DB, q *queue.Queue)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if err := schema.Up(t.Context(), db, quiet()); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)
		fn(t, db, queue.New(db, opts))
	})
}

func TestWorkIsHandedOutOnce(t *testing.T) {
	// The reason this package has engine-specific SQL in it. Two workers
	// reading the same row and both updating it means the same scan ingested
	// twice — and on a duplicate ingest that would look like real change.
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, q *queue.Queue) {
		ctx := t.Context()
		const jobs = 12
		for i := range jobs {
			if _, err := q.Add(ctx, "ingest", fmt.Sprintf("scan-%d", i)); err != nil {
				t.Fatal(err)
			}
		}

		const workers = 6
		var mu sync.Mutex
		claimed := map[int64]string{}
		duplicates := 0

		var wg sync.WaitGroup
		start := make(chan struct{})
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				name := fmt.Sprintf("worker-%d", w)
				<-start
				for {
					job, err := q.Claim(ctx, name, "ingest")
					if err != nil {
						t.Errorf("%s: claim: %v", name, err)
						return
					}
					if job == nil {
						return
					}
					mu.Lock()
					if prior, seen := claimed[job.ID]; seen {
						duplicates++
						t.Errorf("job %d claimed by %s and again by %s", job.ID, prior, name)
					}
					claimed[job.ID] = name
					mu.Unlock()
					if err := q.Succeed(ctx, job.ID, name); err != nil {
						t.Errorf("succeed: %v", err)
					}
				}
			}()
		}
		close(start)
		wg.Wait()

		if duplicates > 0 {
			t.Errorf("%d jobs were handed out more than once", duplicates)
		}
		if len(claimed) != jobs {
			t.Errorf("%d of %d jobs were done", len(claimed), jobs)
		}
	})
}

func TestNothingToDoReturnsNothing(t *testing.T) {
	each(t, queue.DefaultOptions(), func(t *testing.T, _ *database.DB, q *queue.Queue) {
		job, err := q.Claim(t.Context(), "worker", "ingest")
		if err != nil {
			t.Fatalf("claim on an empty queue: %v", err)
		}
		if job != nil {
			t.Errorf("got %+v from an empty queue", job)
		}
	})
}

func TestFailedWorkComesBackLater(t *testing.T) {
	each(t, queue.DefaultOptions(), func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		if _, err := q.Add(ctx, "ingest", "x"); err != nil {
			t.Fatal(err)
		}
		job, err := q.Claim(ctx, "worker", "ingest")
		if err != nil || job == nil {
			t.Fatalf("claim: %v %+v", err, job)
		}
		if err := q.Fail(ctx, job.ID, "worker", errors.New("upstream unavailable")); err != nil {
			t.Fatal(err)
		}
		// Held back deliberately, so a dependency that is briefly unavailable
		// is not hammered while it recovers.
		again, err := q.Claim(ctx, "worker", "ingest")
		if err != nil {
			t.Fatal(err)
		}
		if again != nil {
			t.Error("failed work was handed straight back out with no delay")
		}
	})
}

func TestWorkThatKeepsFailingIsSetAside(t *testing.T) {
	// Without a limit, one job that can never succeed retries for ever and
	// crowds out work that could.
	opts := queue.DefaultOptions()
	opts.MaxAttempts = 3
	opts.Backoff = 0 // retry immediately, so the test does not wait
	each(t, opts, func(t *testing.T, db *database.DB, q *queue.Queue) {
		ctx := t.Context()
		if _, err := q.Add(ctx, "ingest", "doomed"); err != nil {
			t.Fatal(err)
		}
		for attempt := 1; attempt <= opts.MaxAttempts; attempt++ {
			job, err := q.Claim(ctx, "worker", "ingest")
			if err != nil {
				t.Fatal(err)
			}
			if job == nil {
				t.Fatalf("nothing to claim on attempt %d", attempt)
			}
			if err := q.Fail(ctx, job.ID, "worker", errors.New("still broken")); err != nil {
				t.Fatal(err)
			}
		}
		if job, err := q.Claim(ctx, "worker", "ingest"); err != nil || job != nil {
			t.Errorf("work was retried past its limit: %+v %v", job, err)
		}
		var state string
		if err := db.QueryRowContext(ctx, "SELECT state FROM job WHERE reference = ?", "doomed").Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state != string(queue.Dead) {
			t.Errorf("state is %q, want %q", state, queue.Dead)
		}
	})
}

func TestAStaleClaimIsTakenOverByAnotherWorker(t *testing.T) {
	// A worker that dies mid-job would otherwise strand the work for ever.
	opts := queue.DefaultOptions()
	opts.ClaimTimeout = time.Millisecond
	each(t, opts, func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		if _, err := q.Add(ctx, "ingest", "abandoned"); err != nil {
			t.Fatal(err)
		}
		first, err := q.Claim(ctx, "worker-that-dies", "ingest")
		if err != nil || first == nil {
			t.Fatalf("first claim: %v", err)
		}
		time.Sleep(20 * time.Millisecond)

		second, err := q.Claim(ctx, "worker-that-lives", "ingest")
		if err != nil {
			t.Fatal(err)
		}
		if second == nil {
			t.Fatal("the abandoned job was never picked up")
		}
		if second.ID != first.ID {
			t.Errorf("picked up job %d, expected %d", second.ID, first.ID)
		}
		if second.Attempts != 2 {
			t.Errorf("attempts is %d after a retake, want 2", second.Attempts)
		}
	})
}

func TestABacklogThatIsTooDeepIsRefused(t *testing.T) {
	// A runaway producer must not be able to push everyone else's work behind
	// its own.
	opts := queue.DefaultOptions()
	opts.MaxBacklog = 3
	each(t, opts, func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		for i := range opts.MaxBacklog {
			if _, err := q.Add(ctx, "ingest", fmt.Sprintf("scan-%d", i)); err != nil {
				t.Fatalf("adding %d: %v", i, err)
			}
		}
		if _, err := q.Add(ctx, "ingest", "one too many"); !errors.Is(err, queue.ErrBacklogFull) {
			t.Errorf("error is %v, want ErrBacklogFull", err)
		}
		// Doing some of the work must make room again.
		job, err := q.Claim(ctx, "worker", "ingest")
		if err != nil || job == nil {
			t.Fatal(err)
		}
		if err := q.Succeed(ctx, job.ID, "worker"); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Add(ctx, "ingest", "now there is room"); err != nil {
			t.Errorf("still refused after work was done: %v", err)
		}
	})
}

func TestOldestWorkGoesFirst(t *testing.T) {
	each(t, queue.DefaultOptions(), func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		for _, ref := range []string{"first", "second", "third"} {
			if _, err := q.Add(ctx, "ingest", ref); err != nil {
				t.Fatal(err)
			}
		}
		for _, want := range []string{"first", "second", "third"} {
			job, err := q.Claim(ctx, "worker", "ingest")
			if err != nil || job == nil {
				t.Fatalf("claim %s: %v", want, err)
			}
			if job.Reference != want {
				t.Errorf("got %q, want %q", job.Reference, want)
			}
			if err := q.Succeed(ctx, job.ID, "worker"); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestAWorkerDoesNotTakeAnotherKindOfWork(t *testing.T) {
	// Workers of different sorts share one queue. One taking another's work
	// would not fail: a job's reference means something different to each of
	// them, so the wrong worker would act on it, get an answer, and mark it
	// done. The work it was meant for simply never happens.
	each(t, queue.DefaultOptions(), func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		if _, err := q.Add(ctx, "ingest", "42"); err != nil {
			t.Fatal(err)
		}

		other, err := q.Claim(ctx, "scanner", "vulnerability.scan")
		if err != nil {
			t.Fatal(err)
		}
		if other != nil {
			t.Fatalf("a scanner took %q work referring to %q", other.Kind, other.Reference)
		}

		mine, err := q.Claim(ctx, "reader", "ingest")
		if err != nil || mine == nil {
			t.Fatalf("the work was not there for the worker it was left for (%v)", err)
		}
		if mine.Reference != "42" {
			t.Errorf("claimed %q", mine.Reference)
		}
	})
}

func TestOnlyTheWorkerHoldingAJobMayFinishIt(t *testing.T) {
	// A worker that ran long enough for its claim to go stale is still running
	// when another takes the job over. Without the condition, whichever
	// finishes first records the ending of what the other is in the middle of
	// — a job marked done while a second worker is still working it, or
	// handed back for retry while it is being finished.
	// The clock is the test's, not the wall's: a claim goes stale when the
	// test says time has passed. Waiting for it instead made the second
	// retake find the first one's claim already stale — under the race
	// detector, and on engines storing the moment to the second — and the
	// test then held one job twice.
	opts := queue.DefaultOptions()
	each(t, opts, func(t *testing.T, db *database.DB, q *queue.Queue) {
		ctx := t.Context()
		moment := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
		queue.SetClock(q, func() time.Time { return moment })
		for _, ref := range []string{"finished-late", "failed-late"} {
			if _, err := q.Add(ctx, "ingest", ref); err != nil {
				t.Fatal(err)
			}
		}
		var lost []*queue.Job
		for range 2 {
			job, err := q.Claim(ctx, "slow", "ingest")
			if err != nil || job == nil {
				t.Fatalf("first claim: %v", err)
			}
			lost = append(lost, job)
		}
		moment = moment.Add(opts.ClaimTimeout + time.Minute)
		var taken []*queue.Job
		for range 2 {
			job, err := q.Claim(ctx, "fresh", "ingest")
			if err != nil || job == nil {
				t.Fatalf("retake: %v", err)
			}
			taken = append(taken, job)
		}
		if taken[0].ID == taken[1].ID {
			t.Fatalf("the retake claimed job %d twice", taken[0].ID)
		}

		// The slow worker finishes both, one way each. Neither is its to
		// finish any more.
		if err := q.Succeed(ctx, lost[0].ID, "slow"); !errors.Is(err, queue.ErrNoLongerHeld) {
			t.Errorf("a stale worker succeeding a retaken job got %v, want ErrNoLongerHeld", err)
		}
		if err := q.Fail(ctx, lost[1].ID, "slow", errors.New("gave up")); !errors.Is(err, queue.ErrNoLongerHeld) {
			t.Errorf("a stale worker failing a retaken job got %v, want ErrNoLongerHeld", err)
		}
		for _, job := range taken {
			var row queue.Job
			if err := db.DB.NewSelect().Model(&row).Where("id = ?", job.ID).Scan(ctx); err != nil {
				t.Fatal(err)
			}
			if row.State != queue.Running || row.ClaimedBy == nil || *row.ClaimedBy != "fresh" {
				t.Errorf("job %d is %s held by %v after a stale worker finished it, want running and held by fresh",
					row.ID, row.State, row.ClaimedBy)
			}
		}

		// And the worker that holds them finishes them as usual.
		if err := q.Succeed(ctx, taken[0].ID, "fresh"); err != nil {
			t.Errorf("the holder could not finish its job: %v", err)
		}
		if err := q.Fail(ctx, taken[1].ID, "fresh", errors.New("gave up")); err != nil {
			t.Errorf("the holder could not hand its job back: %v", err)
		}
	})
}

func TestSettlingOutlivesTheCancellationThatEndedTheWork(t *testing.T) {
	// The record of how a job ended is written after the work, which on a
	// shutdown means after the cancellation that interrupted it. Written with
	// the canceled context it fails, and the job stays claimed by a process
	// that has gone until the claim goes stale.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	settled, done := queue.Settling(ctx)
	defer done()
	if settled.Err() != nil {
		t.Fatalf("a settling context is already over: %v", settled.Err())
	}
	if _, bounded := settled.Deadline(); !bounded {
		t.Error("a settling context has no bound, so a database that is not answering holds a shutdown for ever")
	}
}

func TestARenewedClaimIsNotTakenOver(t *testing.T) {
	// The claim timeout bounds how long a worker may go silent, not how long a
	// job may take. Without renewal, a scan of a large image outlives its
	// claim and a second worker scans the same target alongside the first —
	// which the conditional update cannot prevent, because from the database's
	// point of view the second claim is legitimate.
	//
	// The clock is the test's: a claim goes stale when the test says time has
	// passed, so this pins the comparison rather than a wait.
	opts := queue.DefaultOptions()
	each(t, opts, func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		moment := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
		queue.SetClock(q, func() time.Time { return moment })
		if _, err := q.Add(ctx, "ingest", "slow-but-alive"); err != nil {
			t.Fatal(err)
		}
		job, err := q.Claim(ctx, "slow", "ingest")
		if err != nil || job == nil {
			t.Fatalf("claim: %v %+v", err, job)
		}

		// Time passes, well past the timeout from when the job was claimed,
		// and the worker says so as it goes.
		for range 3 {
			moment = moment.Add(opts.ClaimTimeout / 2)
			if err := q.Renew(ctx, job.ID, "slow"); err != nil {
				t.Fatalf("renewing at %s: %v", moment, err)
			}
		}
		if other, err := q.Claim(ctx, "fresh", "ingest"); err != nil {
			t.Fatal(err)
		} else if other != nil {
			t.Errorf("a job still being worked on was taken over %s after it was claimed",
				3*(opts.ClaimTimeout/2))
		}

		// And it stops being held once the renewals stop, which is the half of
		// this that keeps a dead worker from stranding the work.
		moment = moment.Add(opts.ClaimTimeout + time.Minute)
		if other, err := q.Claim(ctx, "fresh", "ingest"); err != nil || other == nil {
			t.Errorf("a job nobody is renewing any more was never picked up: %v", err)
		}
	})
}

func TestOnlyTheWorkerHoldingAJobMayRenewIt(t *testing.T) {
	// A renewal from a worker that lost its claim must not take the job back
	// from whoever holds it now — that would leave two workers each believing
	// the job is theirs, and the second one has already started.
	opts := queue.DefaultOptions()
	each(t, opts, func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		moment := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
		queue.SetClock(q, func() time.Time { return moment })
		if _, err := q.Add(ctx, "ingest", "handed-on"); err != nil {
			t.Fatal(err)
		}
		lost, err := q.Claim(ctx, "slow", "ingest")
		if err != nil || lost == nil {
			t.Fatalf("first claim: %v %+v", err, lost)
		}
		moment = moment.Add(opts.ClaimTimeout + time.Minute)
		taken, err := q.Claim(ctx, "fresh", "ingest")
		if err != nil || taken == nil {
			t.Fatalf("retake: %v %+v", err, taken)
		}

		if err := q.Renew(ctx, lost.ID, "slow"); !errors.Is(err, queue.ErrNoLongerHeld) {
			t.Errorf("a worker that lost its claim renewed it anyway: %v", err)
		}
		// The holder may, and does so at the moment it claimed at — so
		// the write changes no value and still has to report the row
		// as matched . Read as rows changed, this is where the holder
		// would be told it no longer holds its own job.
		if err := q.Renew(ctx, taken.ID, "fresh"); err != nil {
			t.Errorf("the holder could not renew its own claim: %v", err)
		}

		// A job that has ended is nobody's to renew.
		if err := q.Succeed(ctx, taken.ID, "fresh"); err != nil {
			t.Fatal(err)
		}
		if err := q.Renew(ctx, taken.ID, "fresh"); !errors.Is(err, queue.ErrNoLongerHeld) {
			t.Errorf("a finished job was renewed: %v", err)
		}
	})
}

func TestWorkStopsWhenItsJobIsTakenOver(t *testing.T) {
	// Renewal is what keeps a long job's claim alive, and losing it anyway is
	// the case that has to end the work: from that moment two workers are
	// doing the same job, and this is the one whose ending nobody will record.
	opts := queue.DefaultOptions()
	opts.Heartbeat = 5 * time.Millisecond
	each(t, opts, func(t *testing.T, db *database.DB, q *queue.Queue) {
		ctx := t.Context()
		moment := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
		queue.SetClock(q, func() time.Time { return moment })
		if _, err := q.Add(ctx, "ingest", "taken-over"); err != nil {
			t.Fatal(err)
		}
		job, err := q.Claim(ctx, "slow", "ingest")
		if err != nil || job == nil {
			t.Fatalf("claim: %v %+v", err, job)
		}
		working, release := q.Holding(ctx, job.ID, "slow", quiet())

		// Another worker, further along the clock, finds the claim stale and
		// takes the job. The slow worker's renewals write the moment its own
		// clock is at, so they cannot hold the job against a worker that
		// believes the timeout has passed — which is what makes this the
		// outcome rather than a race with the ticker.
		later := queue.New(db, opts)
		queue.SetClock(later, func() time.Time {
			return moment.Add(opts.ClaimTimeout + time.Minute)
		})
		if taken, err := later.Claim(ctx, "fresh", "ingest"); err != nil || taken == nil {
			t.Fatalf("retake: %v %+v", err, taken)
		}

		select {
		case <-working.Done():
		case <-time.After(30 * time.Second):
			t.Fatal("the work was never stopped after its job went to another worker")
		}
		if cause := context.Cause(working); !errors.Is(cause, queue.ErrNoLongerHeld) {
			t.Errorf("the work ended with %v, want ErrNoLongerHeld", cause)
		}
		if lost := release(); !errors.Is(lost, queue.ErrNoLongerHeld) {
			t.Errorf("stopping the renewals reported %v, want ErrNoLongerHeld", lost)
		}
	})
}

func TestRenewalsStopWithTheWorkTheyHeldFor(t *testing.T) {
	// The renewing has to stop when the work does, or something is still
	// writing to the job while the caller records how it ended — and on the
	// engine with one connection, still asking for it.
	opts := queue.DefaultOptions()
	opts.Heartbeat = time.Millisecond
	each(t, opts, func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		if _, err := q.Add(ctx, "ingest", "brief"); err != nil {
			t.Fatal(err)
		}
		job, err := q.Claim(ctx, "worker", "ingest")
		if err != nil || job == nil {
			t.Fatalf("claim: %v %+v", err, job)
		}
		working, release := q.Holding(ctx, job.ID, "worker", quiet())
		if lost := release(); lost != nil {
			t.Errorf("a claim nobody took was reported lost: %v", lost)
		}
		if working.Err() == nil {
			t.Error("the work's context outlived the renewals that held its claim")
		}
		// Whoever held it still holds it, and finishes it as usual.
		if err := q.Succeed(ctx, job.ID, "worker"); err != nil {
			t.Errorf("the holder could not finish its job: %v", err)
		}
	})
}
