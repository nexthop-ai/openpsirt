// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue

import (
	"context"
	"time"
)

// LeaseFor is how long a pass holds its lease, given how often it runs.
//
// Several cycles, so a replica that is briefly slow does not lose the work to
// another and then take it back; at least a minute, so a very short interval
// in a test does not make a lease that has lapsed by the time it is read. What
// keeps it across a long pass is a Renewal, never this number.
func LeaseFor(interval time.Duration) time.Duration {
	return max(5*interval, time.Minute)
}

// RenewEvery is how many steps a Renewal lets a pass take before it takes the
// lease again: twenty-five requests at the outward timeout is well inside a
// lease, and the pass is not a conditional update on every request.
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
