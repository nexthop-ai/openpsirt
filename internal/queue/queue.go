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

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/setting"
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
	// MaxBacklog caps how much work of one kind may be waiting. Beyond it,
	// new work of that kind is refused so a runaway producer cannot push
	// everyone else's work behind its own.
	//
	// Per kind rather than across the queue, because one cap shared between
	// kinds is the opposite of what it says: the producer that filled it
	// keeps its place and every other producer is refused.
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
	// MaxHold is how long one claim may be renewed for in total, after which
	// the renewals stop and the work is cancelled.
	//
	// Renewal has no other exit. A unit of work that never returns is held
	// and renewed for ever, so the job never goes stale, is never handed to
	// another worker, never fails and never reaches the state work that
	// cannot succeed ends in — and nothing counts it, because the queue's
	// depth counts what is waiting. The claim timeout does not cover this:
	// it bounds a worker going silent, and a wedged worker is not silent.
	//
	// A small multiple of the claim timeout, because it has to exceed the
	// longest legitimate single unit of work. Zero is no ceiling, which is
	// what a caller running work with no upper bound of its own asks for
	// explicitly rather than by omission.
	MaxHold time.Duration
	// Backoff is how long to wait before retrying, multiplied by the attempt.
	Backoff time.Duration
}

// DefaultOptions suit ingest: work measured in seconds to minutes, and a
// producer that will retry on its own if we refuse.
func DefaultOptions() Options {
	return Options{
		MaxAttempts: 5,
		// The same number the settings screen reports as shipped. Written in
		// one place, because these are read by different things — the screen
		// reports the setting package's, the queue falls back to this one —
		// and two spellings disagree the first time either moves.
		MaxBacklog:   setting.DefaultQueueBacklog,
		ClaimTimeout: 30 * time.Minute,
		Heartbeat:    5 * time.Minute,
		// Four claim timeouts. The longest unit of work here is a scan, whose
		// own bound defaults to one claim timeout, so this leaves room for a
		// deployment to raise that several times over before the ceiling is
		// what stops it.
		MaxHold: 2 * time.Hour,
		Backoff: 30 * time.Second,
	}
}

// Check reports a set of bounds that cannot work together.
//
// The bounds are a deployment's to size, and two of them are only meaningful
// against each other. Refused as the process starts rather than discovered
// later: what a wrong pair produces is work handed to a second worker while
// the first is still doing it, which looks like a fault in the work.
func (o Options) Check() error {
	if o.Heartbeat > 0 && o.ClaimTimeout > 0 && o.Heartbeat >= o.ClaimTimeout {
		return fmt.Errorf(
			"OPENPSIRT_QUEUE_HEARTBEAT is %s and OPENPSIRT_QUEUE_CLAIM_TIMEOUT is %s: "+
				"a claim renewed no more often than it goes stale is handed to a second "+
				"worker while the first is still holding it", o.Heartbeat, o.ClaimTimeout)
	}
	if o.MaxHold > 0 && o.ClaimTimeout > 0 && o.MaxHold <= o.ClaimTimeout {
		return fmt.Errorf(
			"OPENPSIRT_QUEUE_MAX_HOLD is %s and OPENPSIRT_QUEUE_CLAIM_TIMEOUT is %s: "+
				"a ceiling on one hold that is not above the claim timeout cancels work "+
				"that is running normally", o.MaxHold, o.ClaimTimeout)
	}
	return nil
}

// Queue hands out work and records what happened to it.
type Queue struct {
	db   *database.DB
	opts Options
	now  func() time.Time
	// Whether the claim holds the row it is about to take. Always true for a
	// queue anything but a test builds, and a field rather than an option
	// because the only thing that turns it off is the test that demonstrates
	// exclusivity does not rest on it.
	locking bool
}

// New returns a queue over db.
func New(db *database.DB, opts Options) *Queue {
	return &Queue{
		db:      db,
		opts:    opts,
		now:     func() time.Time { return time.Now().UTC() },
		locking: true,
	}
}

// Add puts work on the queue, refusing it when the backlog is already too deep.
//
// The depth and the insert go in one transaction, so the count the refusal
// rests on is the count at the moment of the write rather than one taken
// beforehand, and a commit a cluster refuses is tried again rather than
// reported as work that could not be queued.
func (q *Queue) Add(ctx context.Context, kind, reference string) (*Job, error) {
	var job *Job
	err := database.InTransaction(ctx, q.db.DB, func(ctx context.Context, tx bun.Tx) error {
		// Every attempt starts from nothing: an attempt that was rolled back
		// describes a queue that no longer exists.
		job = nil
		added, err := q.AddTx(ctx, tx, kind, reference)
		if err != nil {
			return err
		}
		job = added
		return nil
	})
	if err != nil {
		return nil, err
	}
	return job, nil
}

// AddTx is Add within a caller's transaction.
//
// Work that describes something else the same transaction wrote has to commit
// with it. A job committed on its own can be claimed before the rows it refers
// to exist; rows committed without their job are work nobody will ever pick
// up, and neither failure announces itself.
func (q *Queue) AddTx(ctx context.Context, db bun.IDB, kind, reference string) (*Job, error) {
	// Read as the work is queued rather than when the queue was built, so a
	// number an administrator changes takes effect on the next upload rather
	// than on the next restart.
	limit, err := q.backlogLimit(ctx, db)
	if err != nil {
		return nil, err
	}
	depth, err := q.depthIn(ctx, db, kind)
	if err != nil {
		return nil, err
	}
	if depth >= limit {
		return nil, fmt.Errorf("%w: %d %s jobs waiting, limit is %d",
			ErrBacklogFull, depth, kind, limit)
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

// Depth counts work of one kind waiting to be done.
//
// Per kind, because the cap it feeds exists so that a runaway producer cannot
// push everyone else's work behind its own — and counted across every kind,
// the runaway producer's work is exactly what stays queued while everybody
// else is refused. A bulk change to the routing rules would otherwise refuse
// every scan upload in the deployment.
func (q *Queue) Depth(ctx context.Context, kind string) (int, error) {
	return q.depthIn(ctx, q.db, kind)
}

func (q *Queue) depthIn(ctx context.Context, db bun.IDB, kind string) (int, error) {
	// Waiting, plus what is held by a worker that has stopped reporting.
	//
	// Counting only what is pending reads a queue in the middle of a reclaim
	// cycle as empty: every row sits in the running state, held by workers
	// that died, and the one number an operator has says there is nothing to
	// do. A claim past its timeout is work waiting for whoever takes it next,
	// which is what this counts.
	stale := q.now().Truncate(time.Microsecond).Add(-q.opts.ClaimTimeout)
	n, err := db.NewSelect().Model((*Job)(nil)).
		Where("kind = ?", kind).
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

// MaxBacklog is how much work of one kind may be waiting before more of that
// kind is refused, as this queue was built. Where a deployment has set its own
// number, Backlog is what is in force.
func (q *Queue) MaxBacklog() int { return q.opts.MaxBacklog }

// Backlog is the limit in force, which is what an administrator set or the
// number this queue was built with.
func (q *Queue) Backlog(ctx context.Context) (int, error) {
	return q.backlogLimit(ctx, q.db)
}

// backlogLimit answers what a deployment has set, falling back to the number
// this queue was built with.
//
// A setting rather than a constant, because the producer a refusal lands on is
// a build server: an estate that pushes more work in than the workers drain
// has no remedy for a compiled-in number short of a new binary, and waiting is
// not one when the thing waiting is CI.
func (q *Queue) backlogLimit(ctx context.Context, db bun.IDB) (int, error) {
	limit, err := setting.NewStore(db).Count(ctx, setting.QueueBacklog, q.opts.MaxBacklog)
	if err != nil {
		return 0, err
	}
	return limit, nil
}

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
		id, err := claimableID(ctx, tx, q.db.Server.Engine, q.locking, kind, now, staleBefore)
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
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("claim job %d: %w", id, err)
		}
		if n == 0 {
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

	var buried int
	err := database.InTransaction(ctx, q.db.DB, func(ctx context.Context, tx bun.Tx) error {
		// Every attempt starts from nothing: a count from an attempt that was
		// rolled back describes a queue that no longer exists.
		buried = 0
		res, err := tx.NewUpdate().Model((*Job)(nil)).
			Set("state = ?", Dead).
			Set("last_error = ?", ErrWorkerGone.Error()).
			Set("claimed_by = NULL").
			Set("updated_at = ?", now).
			Where("state = ?", Running).
			Where("claimed_at < ?", stale).
			Where("attempts >= max_attempts").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("set aside work whose worker never came back: %w", err)
		}
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("set aside work whose worker never came back: %w", err)
		}
		buried = int(n)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return buried, nil
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

// ErrHeldTooLong ends work that has been held past the ceiling on one claim.
//
// The work did not report anything, which is what separates this from a
// failure: the worker is still inside it and nothing will come back. Ending
// the claim is what lets the job go stale and be handed out again.
var ErrHeldTooLong = errors.New("the claim on this job was held past its ceiling")

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
	return database.InTransaction(ctx, q.db.DB, func(ctx context.Context, tx bun.Tx) error {
		return q.renewIn(ctx, tx, id, worker)
	})
}

func (q *Queue) renewIn(ctx context.Context, tx bun.Tx, id int64, worker string) error {
	now := q.now().Truncate(time.Microsecond)
	res, err := tx.NewUpdate().Model((*Job)(nil)).
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
	started := q.now()
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
			// A ceiling on the whole hold, not on one renewal. Without it the
			// only exits are the work finishing and the claim being taken
			// away, so work that never returns is renewed for ever and the
			// job is stranded in a state nothing reports.
			//
			// Logged at Error: a hold that reached its ceiling is a worker
			// that is not coming back, which is the one event here an
			// operator has to see.
			if held := q.now().Sub(started); q.opts.MaxHold > 0 && held >= q.opts.MaxHold {
				logger.Error("work has been held past the ceiling on one claim, "+
					"so the claim is being given up and the work cancelled",
					"job", id, "worker", worker, "held", held, "ceiling", q.opts.MaxHold)
				lost = ErrHeldTooLong
				give(ErrHeldTooLong)
				return
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
	return database.InTransaction(ctx, q.db.DB, func(ctx context.Context, tx bun.Tx) error {
		now := q.now().Truncate(time.Microsecond)
		res, err := tx.NewUpdate().Model((*Job)(nil)).
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
		if err := held(res); err == nil {
			return nil
		}
		// Nothing matched, which on a first attempt means the claim is
		// somebody else's now. On a retry it also covers a commit that
		// succeeded and whose answer never arrived, so the question is asked
		// of the row rather than assumed: work that is finished is finished,
		// and reporting a lost claim for it would have the caller record a
		// failure against a job that succeeded.
		ending := new(Job)
		if err := tx.NewSelect().Model(ending).Where("id = ?", id).Scan(ctx); err != nil {
			return ErrNoLongerHeld
		}
		if ending.State == Done {
			return nil
		}
		return ErrNoLongerHeld
	})
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
			Set("last_error = ?", head(cause.Error(), mostOfAnError)).
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

// mostOfAnError bounds what a failing job may write about itself.
//
// The string comes from whatever failed — a parser, a scanner's output, a
// driver — and is stored and then handed back to whoever asks about their
// upload. Unbounded, one job can write as much as its cause felt like saying
// into a column every reader of that job then carries.
//
// Generous, because the first lines of a parser's complaint are what make it
// actionable and cutting them makes the field useless. The worker's own log
// line carries the whole of it either way.
const mostOfAnError = 4096

// head is the first n bytes of s, cut between characters and marked where it
// was cut.
//
// A cut at a byte offset splits a multi-byte character and leaves an invalid
// tail, which three of the four engines then refuse to store — so the bound
// meant to keep a write small is what makes it fail. The cut itself is the
// shared one: this spelled it a second time, correctly, which is how the
// spellings that are not correct survive.
func head(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const cut = "…"
	room := n - len(cut)
	if room <= 0 {
		return ""
	}
	return bound.Head(s, room) + cut
}

// held reads a conditional update's count as whether the job was still this
// worker's. Rows matched rather than rows changed, which the connection
// settings make true on every engine.
//
// A count that cannot be read is not zero. Read as one, every ending a worker
// recorded would report the job lost and nothing would ever be settled.
func held(res sql.Result) error {
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("find out whether this job is still ours: %w", err)
	}
	if n == 0 {
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
func (q *Queue) SetAside(ctx context.Context, limit int) ([]Job, int, error) {
	if limit <= 0 || limit > setAsideCeiling {
		limit = setAsideCeiling
	}
	var jobs []Job
	if err := q.db.NewSelect().Model(&jobs).
		Where("state = ?", Dead).
		OrderExpr("updated_at DESC, id DESC").
		Limit(limit).Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("list work that was set aside: %w", err)
	}
	// Counted as well as listed. A page that stops at the cap with nothing
	// saying so cannot be told from a complete answer, and a restart loop
	// sets aside far more than one page holds — which is exactly the state
	// somebody opens this in.
	total, err := q.db.NewSelect().Model((*Job)(nil)).
		Where("state = ?", Dead).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count work that was set aside: %w", err)
	}
	return jobs, total, nil
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
	return database.InTransaction(ctx, q.db.DB, func(ctx context.Context, tx bun.Tx) error {
		now := q.now().Truncate(time.Microsecond)
		res, err := tx.NewUpdate().Model((*Job)(nil)).
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
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("put job %d back: %w", id, err)
		}
		if n == 0 {
			return ErrNotSetAside
		}
		return nil
	})
}

// Ending is how a worker settled one job, and whether the job had already gone
// to somebody else.
type Ending struct {
	// HandedOver says the claim went to another worker while the work ran. The
	// work that was done stands; the job's ending is the other worker's to
	// write, so there is nothing here to retry.
	HandedOver bool
	// Err is what the caller should surface, which is the work's own failure
	// where there was one and the failure to record an ending where there was
	// not.
	Err error
}

// Settle records how a job ended, whatever stopped the work.
//
// Here rather than in each worker. The sequence — open a context that outlives
// a cancellation, record the ending against it, tell a stale claim apart from
// a write that failed, and notice a takeover — was written out in both workers
// down to the comment paragraph, and they had begun to disagree. A third
// worker would have been a third copy, and the rule for a job finished by a
// worker that no longer holds it would then have three readings.
//
// noun is what the reference is called in a log line, because "scan" and
// "target" are the same field to this package and not to an operator reading
// it. recover runs only where the failure is the work's own — not on a
// cancellation and not on a takeover — which is the one respect the two
// workers genuinely differ; it is a closure rather than a flag so that the
// difference stays visible at the call site.
func (q *Queue) Settle(ctx context.Context, job *Job, worker, noun string,
	logger *slog.Logger, work error, taken error, recover func(context.Context) error) Ending {

	// A shutdown cancels the work, and the cancellation must not also stop the
	// job being handed back — otherwise it stays claimed by a process that has
	// gone until the claim goes stale, half an hour later.
	settled, done := Settling(ctx)
	defer done()

	// A claim given up at its ceiling is this job's own failure rather than a
	// handover: nobody else has it, and the attempt has to be counted or the
	// job is retried for ever.
	ceiling := errors.Is(taken, ErrHeldTooLong)

	var ended error
	if work != nil {
		if recover != nil && ctx.Err() == nil && (taken == nil || ceiling) {
			if err := recover(settled); err != nil && logger != nil {
				logger.Warn("could not record why work failed",
					"job", job.ID, noun, job.Reference, "error", err)
			}
		}
		ended = q.Fail(settled, job.ID, worker, work)
	} else {
		ended = q.Succeed(settled, job.ID, worker)
	}

	out := Ending{Err: work}
	switch {
	case errors.Is(ended, ErrNoLongerHeld):
		// The claim went stale while the work ran and another worker took the
		// job over. What was done stands; the job's ending is the other
		// worker's to write, so there is nothing to retry here — but work
		// that outran its claim is worth knowing about.
		if logger != nil {
			logger.Warn("a job was finished by a worker that no longer held it",
				"job", job.ID, noun, job.Reference)
		}
	case ended != nil:
		if logger != nil {
			logger.Warn("could not record how a job ended", "job", job.ID, "error", ended)
		}
		if work == nil {
			out.Err = ended
		}
	}

	switch {
	case ceiling:
		// Logged at Error and reported as a failure. The ending was recorded
		// above, so the attempt counts and the job is eventually set aside
		// rather than run again for ever by workers that each wedge in turn.
		if logger != nil {
			logger.Error("work was stopped because its claim reached the ceiling on one hold",
				"job", job.ID, noun, job.Reference)
		}
	case taken != nil:
		// The work was stopped because the job went to another worker, so the
		// error it ended with describes that rather than anything about the
		// thing being worked on. There is nothing to retry and nothing to
		// report: the job is in hand elsewhere. It is logged because a claim
		// that went stale under running work means the renewals were not
		// landing.
		if logger != nil {
			logger.Warn("work was stopped because another worker took its job over",
				"job", job.ID, noun, job.Reference)
		}
		out.HandedOver = true
		out.Err = nil
	}
	return out
}
