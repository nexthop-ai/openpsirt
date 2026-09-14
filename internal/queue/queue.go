// Package queue is a durable work queue held in the application's own
// database.
//
// It exists rather than a library because the mature Go queues are tied to one
// engine or need a separate service, and neither suits software an operator
// installs against whatever database they already run.
//
// Work survives a restart: a job is a row, and a worker that dies mid-job
// leaves it claimed until the claim goes stale, after which another worker
// takes it. Losing an ingest because a pod was rescheduled would mean a scan
// silently never arriving.
package queue

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// State is where a job has got to.
type State string

const (
	// Pending work is waiting to be claimed.
	Pending State = "pending"
	// Running work is claimed by a worker.
	Running State = "running"
	// Done work succeeded.
	Done State = "done"
	// Dead work failed more times than it is allowed to.
	Dead State = "dead"
)

// Job is one piece of work.
type Job struct {
	bun.BaseModel `bun:"table:job,alias:j"`

	ID   int64  `bun:"id,pk,autoincrement"`
	Kind string `bun:"kind,notnull"`
	// Reference points at what the work is about — a scan, say. The payload
	// itself is never carried here: a job row holds a pointer, so the queue
	// stays small however large the thing being worked on is.
	Reference   string     `bun:"reference,notnull"`
	State       State      `bun:"state,notnull"`
	Attempts    int        `bun:"attempts,notnull"`
	MaxAttempts int        `bun:"max_attempts,notnull"`
	RunAfter    time.Time  `bun:"run_after,notnull"`
	ClaimedBy   *string    `bun:"claimed_by"`
	ClaimedAt   *time.Time `bun:"claimed_at"`
	LastError   *string    `bun:"last_error"`
	CreatedAt   time.Time  `bun:"created_at,notnull"`
	UpdatedAt   time.Time  `bun:"updated_at,notnull"`
}

// ErrBacklogFull is returned when the queue is too deep to take more.
var ErrBacklogFull = errors.New("queue backlog is full")

// Options tune a queue.
type Options struct {
	// MaxAttempts is how many times a job may be tried before it is set aside.
	// Without a limit, a job that can never succeed retries for ever and
	// crowds out work that could.
	MaxAttempts int
	// MaxBacklog caps how much work may be waiting. Beyond it, new work is
	// refused so a runaway producer cannot push everyone else's work behind
	// its own.
	MaxBacklog int
	// ClaimTimeout is how long a claim is honored with nothing heard from the
	// worker holding it, after which another worker may take the job. It
	// bounds how long a worker may go silent, not how long a job may take:
	// Heartbeat is what keeps a running job's claim alive.
	ClaimTimeout time.Duration
	// Heartbeat is how often a worker renews the claim on work it is running.
	// Without it the claim timeout is a ceiling on how long a job may take,
	// and a job that legitimately takes longer is handed to a second worker
	// while the first is still doing it — which the conditional update cannot
	// prevent, because the second claim is legitimate.
	//
	// Well under the claim timeout, so a renewal can fail several times over
	// before the claim is actually at risk. Zero renews nothing.
	Heartbeat time.Duration
	// Backoff is how long to wait before retrying, multiplied by the attempt.
	Backoff time.Duration
}

// DefaultOptions suit ingest: work measured in seconds to minutes, and a
// producer that will retry on its own if we refuse.
func DefaultOptions() Options {
	return Options{
		MaxAttempts:  5,
		MaxBacklog:   1000,
		ClaimTimeout: 30 * time.Minute,
		Heartbeat:    5 * time.Minute,
		Backoff:      30 * time.Second,
	}
}

// Queue hands out work and records what happened to it.
type Queue struct {
	db   *database.DB
	opts Options
	now  func() time.Time
}

// New returns a queue over db.
func New(db *database.DB, opts Options) *Queue {
	return &Queue{db: db, opts: opts, now: func() time.Time { return time.Now().UTC() }}
}

// Add puts work on the queue, refusing it when the backlog is already too deep.
func (q *Queue) Add(ctx context.Context, kind, reference string) (*Job, error) {
	return q.AddTx(ctx, q.db, kind, reference)
}

// AddTx is Add within a caller's transaction.
//
// Work that describes something else the same transaction wrote has to commit
// with it. A job committed on its own can be claimed before the rows it refers
// to exist; rows committed without their job are work nobody will ever pick
// up, and neither failure announces itself.
func (q *Queue) AddTx(ctx context.Context, db bun.IDB, kind, reference string) (*Job, error) {
	depth, err := q.depthIn(ctx, db)
	if err != nil {
		return nil, err
	}
	if depth >= q.opts.MaxBacklog {
		return nil, fmt.Errorf("%w: %d waiting, limit is %d", ErrBacklogFull, depth, q.opts.MaxBacklog)
	}

	now := q.now().Truncate(time.Microsecond)
	job := &Job{
		Kind: kind, Reference: reference, State: Pending,
		MaxAttempts: q.opts.MaxAttempts, RunAfter: now,
		CreatedAt: now, UpdatedAt: now,
	}
	if _, err := db.NewInsert().Model(job).Exec(ctx); err != nil {
		return nil, fmt.Errorf("add job: %w", err)
	}
	return job, nil
}

// Depth counts work waiting to be done.
func (q *Queue) Depth(ctx context.Context) (int, error) { return q.depthIn(ctx, q.db) }

func (q *Queue) depthIn(ctx context.Context, db bun.IDB) (int, error) {
	// Waiting, plus what is held by a worker that has stopped reporting.
	//
	// Counting only what is pending reads a queue in the middle of a reclaim
	// cycle as empty: every row sits in the running state, held by workers
	// that died, and the one number an operator has says there is nothing to
	// do. A claim past its timeout is work waiting for whoever takes it next,
	// which is what this counts.
	stale := q.now().Truncate(time.Microsecond).Add(-q.opts.ClaimTimeout)
	n, err := db.NewSelect().Model((*Job)(nil)).
		WhereGroup(" AND ", func(s *bun.SelectQuery) *bun.SelectQuery {
			return s.
				WhereOr("state = ?", Pending).
				WhereOr("state = ? AND claimed_at < ? AND attempts < max_attempts",
					Running, stale)
		}).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("measure backlog: %w", err)
	}
	return n, nil
}

// MaxBacklog is how much work may be waiting before more is refused.
func (q *Queue) MaxBacklog() int { return q.opts.MaxBacklog }

// Claim takes the oldest runnable job of a kind, or returns nil when there is
// nothing of that kind to do.
//
// The kind is required. Workers of different sorts share one queue, and one
// taking another's work would not fail — a job's reference means something
// different to each of them, so the wrong worker would act on it, get an
// answer, and mark it done.
//
// Two workers must never get the same job. That is guaranteed by the update
// below, which only succeeds if the job is still claimable — portably, on
// every engine. The engine-specific row locking in claim_locking.go is about
// throughput, not correctness.
func (q *Queue) Claim(ctx context.Context, worker, kind string) (*Job, error) {
	now := q.now().Truncate(time.Microsecond)

	// A job whose claim has gone stale is available again: the worker holding
	// it has died, and waiting for it forever would strand the work.
	staleBefore := now.Add(-q.opts.ClaimTimeout)

	var job *Job
	err := database.InTransaction(ctx, q.db.DB, func(ctx context.Context, tx bun.Tx) error {
		// Every attempt starts from nothing. InTransaction re-runs this
		// closure when a commit is refused for a reason worth retrying, and an
		// attempt that claimed a job and was then rolled back would leave the
		// pointer set — so an attempt that finds nothing claimable returns no
		// error and Claim hands back a claim the database does not have.
		job = nil
		id, err := claimableID(ctx, tx, q.db.Server.Engine, kind, now, staleBefore)
		if err != nil || id == 0 {
			return err
		}
		// The update repeats the conditions the select just checked, so it
		// only succeeds if the job is *still* claimable.
		//
		// This is what makes claiming correct, rather than the row locking
		// below it. Locking is a throughput matter: it stops workers queueing
		// behind one another on the same row. If it were the guarantee, then
		// getting it wrong for some future engine would mean handing the same
		// work out twice, which on an ingest looks like real change. This way
		// the worst case is slow.
		res, err := tx.NewUpdate().Model((*Job)(nil)).
			Set("state = ?", Running).
			Set("attempts = attempts + 1").
			Set("claimed_by = ?", worker).
			Set("claimed_at = ?", now).
			Set("updated_at = ?", now).
			Where("id = ?", id).
			WhereGroup(" AND ", func(u *bun.UpdateQuery) *bun.UpdateQuery {
				return u.
					WhereOr("state = ? AND run_after <= ?", Pending, now).
					WhereOr("state = ? AND claimed_at < ? AND attempts < max_attempts",
						Running, staleBefore)
			}).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("claim job %d: %w", id, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Someone else got there first. Nothing to do this round.
			return nil
		}
		job = new(Job)
		return tx.NewSelect().Model(job).Where("id = ?", id).Scan(ctx)
	})
	if err != nil {
		return nil, err
	}
	return job, nil
}

// Bury sets aside work whose worker never came back.
//
// A worker that dies reports nothing, so nothing calls Fail and the row stays
// in the running state holding a claim that has gone stale. Once its attempts
// have run out that claim is no longer reclaimable, and without this it would
// sit there for ever: a producer asking about its upload reads a running row
// as work still in progress, so the failure is never reported and the build is
// never enqueued again.
//
// Its own pass rather than work done on the way past a claim. Folded into the
// claim it is a range update every worker runs on every poll, over the rows
// every other worker is claiming — which on MySQL deadlocks six workers
// against each other rather than handing out work.
//
// Written as the failure Fail would have written. To everything downstream it
// is the same failure; the difference is only that nobody was left alive to
// report it.
func (q *Queue) Bury(ctx context.Context) (int, error) {
	now := q.now().Truncate(time.Microsecond)
	stale := now.Add(-q.opts.ClaimTimeout)

	res, err := q.db.NewUpdate().Model((*Job)(nil)).
		Set("state = ?", Dead).
		Set("last_error = ?", ErrWorkerGone.Error()).
		Set("claimed_by = NULL").
		Set("updated_at = ?", now).
		Where("state = ?", Running).
		Where("claimed_at < ?", stale).
		Where("attempts >= max_attempts").
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("set aside work whose worker never came back: %w", err)
	}
	buried, err := res.RowsAffected()
	if err != nil {
		// The count is the only thing lost; the statement said it succeeded.
		return 0, nil
	}
	return int(buried), nil
}

// ErrWorkerGone is what a job records when the worker holding it never
// reported back. It is the last_error somebody reads on the set-aside row,
// and it is deliberately not the words of any particular failure: nothing
// observed one.
var ErrWorkerGone = errors.New("the worker holding this job never reported back")

// ErrNoLongerHeld says the job was not this worker's to finish: its claim went
// stale and another worker took it, or it has already been finished. Whoever
// holds it now will record how it ended, so the caller has nothing to retry.
var ErrNoLongerHeld = errors.New("the job is no longer held by this worker")

// Settling is a context for recording how a job ended.
//
// The record is written after the work — including after the shutdown that
// interrupted it — so it carries the cancellation no further than a bound of
// its own. A job whose ending is never written stays claimed by a worker that
// has gone, and nobody else may touch it until the claim goes stale.
func Settling(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
}

// settleTimeout bounds the writes that record how a job ended, once nothing
// else is holding them to a deadline. Long enough for a database that is
// answering; short enough that a shutdown is not held by one that is not.
const settleTimeout = 5 * time.Second

// Renew extends this worker's claim on work it is still running, by the worker
// that holds it.
//
// A claim says when the worker holding it was last heard from. Renewing it is
// what lets a job take longer than a claim is honored for without a second
// worker taking it over: a scan of a large image legitimately runs for a long
// time, and the one thing the conditional update in Claim cannot prevent is a
// second claim the database considers legitimate.
//
// A renewal on a job this worker no longer holds is ErrNoLongerHeld. That is
// the answer that matters — the work is being done twice from that moment —
// and it is what Holding watches for.
func (q *Queue) Renew(ctx context.Context, id int64, worker string) error {
	now := q.now().Truncate(time.Microsecond)
	res, err := q.db.NewUpdate().Model((*Job)(nil)).
		Set("claimed_at = ?", now).
		Set("updated_at = ?", now).
		Where("id = ?", id).
		Where("state = ?", Running).
		Where("claimed_by = ?", worker).
		Exec(ctx)
	if err != nil {
		return err
	}
	return held(res)
}

// Holding renews a claim for as long as its work runs.
//
// The returned context is the one the work runs under, and it ends if another
// worker takes the job over — with ErrNoLongerHeld as its cause. Stopping is
// the right answer there: from that moment the work is being done twice, and
// this is the copy whose ending nobody will record, so carrying on spends a
// scanner run and a pile of writes to lose a race that is already lost.
//
// The returned function stops the renewals and says whether the claim was
// lost. It must be called once the work has ended, renewals or not, and it
// waits for the renewing to stop so that nothing writes to the job after the
// caller starts recording how it ended.
func (q *Queue) Holding(ctx context.Context, id int64, worker string,
	logger *slog.Logger) (context.Context, func() error) {

	working, give := context.WithCancelCause(ctx)
	if q.opts.Heartbeat <= 0 {
		return working, func() error { give(nil); return nil }
	}

	var lost error
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(q.opts.Heartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-working.Done():
				return
			case <-ticker.C:
			}
			// Bounded by the interval: a renewal still waiting when the next
			// one is due has already failed, and on SQLite it is waiting for
			// the single connection the work itself is holding.
			//
			// **On that engine it cannot succeed while the work runs**, so
			// the claim timeout is the whole of the protection there rather
			// than a margin around this: it has to exceed the longest single
			// unit of work, or the claim goes stale and the job is run again
			// once the first transaction commits. Kept because it is the
			// whole of the protection on the other three.
			bounded, done := context.WithTimeout(working, q.opts.Heartbeat)
			err := q.Renew(bounded, id, worker)
			done()
			switch {
			case errors.Is(err, ErrNoLongerHeld):
				lost = err
				give(err)
				return
			case err != nil && working.Err() == nil:
				// Not lost yet. The claim stands until the timeout passes with
				// nothing landing, which is several intervals away, so the
				// next tick tries again rather than abandoning the work over
				// one failed write.
				logger.Warn("could not renew the claim on work in progress",
					"job", id, "error", err)
			}
		}
	}()

	return working, func() error {
		give(nil)
		<-stopped
		return lost
	}
}

// Succeed marks work as finished, by the worker that holds it.
//
// Only the holder may finish a job. A worker that ran long enough for its
// claim to go stale is still running when another takes the job over, and
// without the condition the first to finish marks done whatever the second is
// in the middle of. That case is reported as ErrNoLongerHeld rather than as a
// failure: the work was done, and its record is the other worker's to write.
func (q *Queue) Succeed(ctx context.Context, id int64, worker string) error {
	now := q.now().Truncate(time.Microsecond)
	res, err := q.db.NewUpdate().Model((*Job)(nil)).
		Set("state = ?", Done).
		Set("claimed_by = NULL").
		Set("updated_at = ?", now).
		Where("id = ?", id).
		Where("state = ?", Running).
		Where("claimed_by = ?", worker).
		Exec(ctx)
	if err != nil {
		return err
	}
	return held(res)
}

// Fail records that work did not succeed, by the worker that holds it.
//
// It goes back on the queue with a delay, unless it has been tried as often as
// it is allowed to be, in which case it is set aside. Retrying for ever would
// let one job that can never succeed crowd out work that could.
func (q *Queue) Fail(ctx context.Context, id int64, worker string, cause error) error {
	// **The attempt count and the write that acts on it, in one act.** The
	// count was read with a bare select and compared in Go, so whether this
	// was the last attempt rested on a value fetched separately from the
	// statement that buries or re-queues the job. The claimed-by predicate
	// makes that mostly safe, and "mostly safe" is not what the rule about
	// reading outside a transaction means.
	return database.InTransaction(ctx, q.db.DB, func(ctx context.Context, tx bun.Tx) error {
		job := new(Job)
		if err := tx.NewSelect().Model(job).Where("id = ?", id).Scan(ctx); err != nil {
			return fmt.Errorf("load job %d: %w", id, err)
		}

		now := q.now().Truncate(time.Microsecond)
		update := tx.NewUpdate().Model((*Job)(nil)).
			Set("last_error = ?", cause.Error()).
			Set("claimed_by = NULL").
			Set("updated_at = ?", now).
			Where("id = ?", id).
			Where("state = ?", Running).
			Where("claimed_by = ?", worker)

		if job.Attempts >= job.MaxAttempts {
			update = update.Set("state = ?", Dead)
		} else {
			// Longer each time, so a dependency that is briefly unavailable is
			// not hammered while it recovers.
			delay := time.Duration(job.Attempts) * q.opts.Backoff
			update = update.Set("state = ?", Pending).Set("run_after = ?", now.Add(delay))
		}
		res, err := update.Exec(ctx)
		if err != nil {
			return err
		}
		return held(res)
	})
}

// held reads a conditional update's count as whether the job was still this
// worker's. Rows matched rather than rows changed, which the connection
// settings make true on every engine.
func held(res sql.Result) error {
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoLongerHeld
	}
	return nil
}

// SetAside lists work that stopped being retried, newest first.
//
// The operator surface over the dead state. Work is set aside rather than
// deleted so that the row and its last error are the evidence of why it
// stopped, and evidence nobody can reach is evidence nobody has: a job that
// stops being retried with nowhere to see it is the same silence as one that
// is retried for ever.
func (q *Queue) SetAside(ctx context.Context, limit int) ([]Job, error) {
	if limit <= 0 || limit > setAsideCeiling {
		limit = setAsideCeiling
	}
	var jobs []Job
	if err := q.db.NewSelect().Model(&jobs).
		Where("state = ?", Dead).
		OrderExpr("updated_at DESC, id DESC").
		Limit(limit).Scan(ctx); err != nil {
		return nil, fmt.Errorf("list work that was set aside: %w", err)
	}
	return jobs, nil
}

// setAsideCeiling bounds the set-aside listing. A read on an interactive route
// carries a cap, and a deployment whose queue has gone wrong is exactly where
// the list is longest.
const setAsideCeiling = 200

// ErrNotSetAside says the job is not one that stopped being retried, so there
// is nothing here to put back.
var ErrNotSetAside = errors.New("that job was not set aside")

// Requeue puts set-aside work back, with its attempts started again.
//
// The attempts are reset rather than the ceiling raised: whoever puts a job
// back has decided the reason it kept failing is dealt with, and a job that
// came back with one attempt left would be set aside again by the next
// transient failure. The last error is kept until something overwrites it, so
// the evidence of the previous run survives the decision to try again.
func (q *Queue) Requeue(ctx context.Context, id int64) error {
	now := q.now().Truncate(time.Microsecond)
	res, err := q.db.NewUpdate().Model((*Job)(nil)).
		Set("state = ?", Pending).
		Set("attempts = ?", 0).
		Set("run_after = ?", now).
		Set("claimed_by = NULL").
		Set("claimed_at = NULL").
		Set("updated_at = ?", now).
		Where("id = ?", id).
		Where("state = ?", Dead).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("put job %d back: %w", id, err)
	}
	// Rows matched rather than rows changed, which the connection settings
	// make true on every engine. Nothing matched means the job is not set
	// aside — already running again, or never there.
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotSetAside
	}
	return nil
}
