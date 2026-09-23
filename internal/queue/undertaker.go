// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"log/slog"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
)

// betweenBurials is how often work abandoned by its worker is looked for.
//
// Unhurried, because what it finds is already past its claim timeout — thirty
// minutes by default — so a pass a few minutes later changes nothing anybody
// can observe. Looking is one statement that matches nothing, which is the
// answer on nearly every pass.
const betweenBurials = 5 * time.Minute

// BurialLease is the name one replica holds while setting aside abandoned
// work. Named here beside the pass that takes it, like the other lease names.
const BurialLease = "queue.bury"

// burialLease outlasts a cycle of the work, which is the rule for every lease
// here: one statement takes well under a cycle, and a lease that lapsed
// mid-pass would let a second replica start the same range update.
const burialLease = 2 * betweenBurials

// Undertaker sets aside work whose worker never came back.
//
// Its own pass rather than work done on the way past a claim: a worker that
// died reports nothing, so no act by anybody is the moment to notice. One
// replica does it, because every replica running the same range update is how
// workers deadlock against one another instead of handing out work.
type Undertaker struct {
	queue   *Queue
	leases  *Leases
	replica string
	logger  *slog.Logger
}

// NewUndertaker returns the pass.
func NewUndertaker(q *Queue, leases *Leases, replica string, logger *slog.Logger) *Undertaker {
	if q == nil {
		return nil
	}
	return &Undertaker{queue: q, leases: leases, replica: replica, logger: logger}
}

// Once sets aside whatever has run out of attempts with nobody left to say so.
func (u *Undertaker) Once(ctx context.Context) (int, error) {
	if u == nil {
		return 0, nil
	}
	// One replica carries, the rest skip. The work may be skipped rather than
	// waited for: what it finds is still there next cycle.
	if u.leases != nil {
		mine, err := u.leases.Take(ctx, BurialLease, u.replica, burialLease)
		if err != nil || !mine {
			return 0, err
		}
	}
	return u.queue.Bury(ctx)
}

// Run buries until the context ends.
func (u *Undertaker) Run(ctx context.Context, interval time.Duration) {
	if u == nil {
		return
	}
	background.Every(ctx, interval, betweenBurials, func(ctx context.Context) {
		// Logged and carried on, like every other background pass here: a
		// pass that cannot run is not a reason to stop serving, and what it
		// failed to set aside is still there on the next one.
		buried, err := u.Once(ctx)
		if err != nil && u.logger != nil {
			u.logger.ErrorContext(ctx, "setting aside work whose worker never came back", "error", err)
		} else if buried > 0 && u.logger != nil {
			// Worth a line at info: work that stopped being retried is
			// something an operator has to know happened.
			u.logger.InfoContext(ctx, "set aside work whose worker never came back", "jobs", buried)
		}
	})
}
