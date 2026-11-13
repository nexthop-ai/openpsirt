// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// RewriteDeadlines queues the rewrite of every stored deadline and urgency a
// policy change makes wrong, inside the transaction making the change.
//
// A queued row outlives a restart and a crash, and a failed attempt is tried
// again up to the queue's attempts, after which the job is recorded failed.
// Committed with the change, so the rewrite cannot run before it.
//
// A rewrite already waiting takes this change too, and nothing is added: it
// reads the policy once its turn comes, so a burst of changes is one waiting
// rewrite. One already running read the policy before this change, so
// another is queued behind it.
func RewriteDeadlines(ctx context.Context, tx bun.IDB, q *queue.Queue) error {
	if q == nil {
		return errors.New("queue the deadline rewrite: this deployment has no queue")
	}
	if err := q.AddUnlessWaitingTx(ctx, tx, queue.Deadlines, rewriteReference); err != nil {
		return fmt.Errorf("queue the deadline rewrite: %w", err)
	}
	return nil
}

// rewriteReference is the reference every deadline rewrite carries. One
// rewrite covers every open finding, so there is nothing else to name.
const rewriteReference = "every open finding"

// deadlineLease names the work of rewriting deadlines, so one replica
// rewrites at a time.
const deadlineLease = "deadline.rewrite"

// deadlineLeaseFor is how long a rewrite holds its turn. Long enough for a
// large estate, short enough that a replica stopping without handing it back
// holds the next rewrite up for no longer.
const deadlineLeaseFor = 30 * time.Minute

// betweenTurnTries is how often a rewrite waiting for its turn asks for it.
// Short against the length of a rewrite, so a turn is not left idle.
const betweenTurnTries = 2 * time.Second

// betweenRewrites is how often this looks for a queued rewrite where the
// caller says nothing.
const betweenRewrites = 10 * time.Second

// Rewriter works the queued deadline rewrites.
type Rewriter struct {
	db     *database.DB
	queue  *queue.Queue
	logger *slog.Logger
	name   string
}

// NewRewriter is the deadline rewrite as a deployment runs it.
func NewRewriter(db *database.DB, q *queue.Queue, logger *slog.Logger, name string) *Rewriter {
	return &Rewriter{db: db, queue: q, logger: logger, name: name}
}

// Run works the rewrite queue until the context ends.
func (r *Rewriter) Run(ctx context.Context, interval time.Duration) {
	background.Drain(ctx, interval, betweenRewrites, func(ctx context.Context) (bool, error) {
		claimed, _, err := r.Once(ctx)
		return claimed, err
	}, func(err error) { r.logger.Error("rewriting deadlines after a policy change", "error", err) })
}

// Once claims one queued rewrite and runs it, reporting whether it claimed
// one and how many findings it rewrote. A failed rewrite is the job's
// failure, tried again by the queue.
func (r *Rewriter) Once(ctx context.Context) (bool, int, error) {
	job, err := r.queue.Claim(ctx, r.name, queue.Deadlines)
	if err != nil || job == nil {
		return false, 0, err
	}
	working, release := r.queue.Holding(ctx, job.ID, r.name, r.logger)
	rewritten, err := r.rewrite(working)
	taken := release()
	ending := r.queue.Settle(ctx, job, r.name, "rewrite", r.logger, err, taken, nil)
	return true, rewritten, ending.Err
}

// rewrite applies the policy in force to every open finding, one replica at a
// time.
//
// The policy is read after the turn is taken. Two replicas each running a
// rewrite would otherwise write what each read when it started, and whichever
// finished last would win, so the stored deadlines could describe a policy
// already superseded. A replica losing the race waits rather than skipping,
// so the last rewrite is the one holding the newest policy.
func (r *Rewriter) rewrite(ctx context.Context) (int, error) {
	leases := queue.NewLeases(r.db.DB)
	if err := leases.Await(ctx, deadlineLease, r.name, deadlineLeaseFor, betweenTurnTries); err != nil {
		return 0, fmt.Errorf("wait for the turn to rewrite deadlines: %w", err)
	}
	// Bounded inside the turn, which began when it was taken, a moment before
	// Await returned: a rewrite never runs on past it beside the next one.
	// The queue tries one ended here again.
	ctx, stop := context.WithTimeout(ctx, deadlineLeaseFor-time.Minute)
	defer stop()
	defer func() {
		// Handed back on a context of its own: the work may have used up its
		// bound, and a turn left held stops the next rewrite until it lapses.
		back, stop := queue.Settling(ctx)
		defer stop()
		if err := leases.Release(back, deadlineLease, r.name); err != nil {
			r.logger.Warn("the deadline rewrite could not hand its turn back", "error", err)
		}
	}()
	windows, err := LoadWindows(ctx, r.db.DB)
	if err != nil {
		return 0, fmt.Errorf("read when things are due: %w", err)
	}
	started := time.Now()
	changed, err := NewStore(r.db.DB).Recompute(ctx, windows)
	if err != nil {
		return changed, fmt.Errorf("rewrite deadlines: %w", err)
	}
	r.logger.Info("deadlines rewritten after a policy change", "findings", changed,
		"took", time.Since(started).Round(time.Millisecond).String())
	return changed, nil
}
