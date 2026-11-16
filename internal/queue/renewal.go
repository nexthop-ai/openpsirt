// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"log/slog"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
)

// LeaseFor is how long a pass holds its lease, given how often it runs.
//
// Several cycles, so a replica that is briefly slow does not lose the work to
// another and then take it back; at least a minute, so a very short interval
// in a test does not make a lease that has lapsed by the time it is read. A
// pass that can outlast it takes the lease again as it runs, through a Renewal
// or before each step; one that does not is held for this alone.
func LeaseFor(interval time.Duration) time.Duration {
	return max(5*interval, time.Minute)
}

// RenewEvery is how many steps a Renewal lets a pass take before it takes the
// lease again, so the pass is not a conditional update on every request. The
// half-lease clock bound is what keeps a slow pass's lease.
const RenewEvery = 25

// Renewal takes a pass's lease again as the pass runs, every RenewEvery steps
// or once half the lease has gone by, whichever comes first. A step is one
// request to somebody else's service or several, so a count alone lets a slow
// one outlast the lease while a second replica takes it.
type Renewal struct {
	take    func(context.Context) (bool, error)
	held    time.Duration
	now     func() time.Time
	renewed time.Time
	steps   int
}

// NewRenewal renews a lease held for held through take, on the clock now.
func NewRenewal(take func(context.Context) (bool, error), held time.Duration, now func() time.Time) *Renewal {
	return &Renewal{take: take, held: held, now: now, renewed: now()}
}

// Keep is asked before each step, and reports whether this replica still holds
// the lease. The first step runs on the lease the pass took to start.
func (r *Renewal) Keep(ctx context.Context) (bool, error) {
	due := r.steps > 0 && (r.steps%RenewEvery == 0 || r.now().Sub(r.renewed) > r.held/2)
	r.steps++
	if !due {
		return true, nil
	}
	mine, err := r.take(ctx)
	if err != nil || !mine {
		return false, err
	}
	r.renewed = r.now()
	return true, nil
}

// Leased is a pass every replica runs on a timer and one at a time does the
// work of, under a lease.
type Leased struct {
	// Name is the lease, and Holder names this replica in it.
	Name   string
	Holder string
	// Interval is how often the pass wakes; a non-positive one takes Fallback.
	Interval time.Duration
	Fallback time.Duration
	// Failing names the work in the line logged when a pass fails.
	Failing string
	Logger  *slog.Logger
}

// RunLeased runs pass on a timer until ctx ends, then hands the lease back so
// another replica takes the work without waiting the lease out. A failed pass
// is logged under Failing and the next one runs on time; a failure that is
// only ctx ending is not logged. Taking the lease and reporting what a pass did
// are the pass's own.
func (l *Leases) RunLeased(ctx context.Context, leased Leased, pass func(context.Context) error) {
	defer l.Handback(ctx, leased.Name, leased.Holder, leased.Logger)
	background.Every(ctx, leased.Interval, leased.Fallback, func(ctx context.Context) {
		if err := pass(ctx); err != nil && ctx.Err() == nil {
			leased.Logger.ErrorContext(ctx, leased.Failing, "error", err)
		}
	})
}
