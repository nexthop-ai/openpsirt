// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package background runs a pass on a timer until its context ends, and starts
// the programs a pass runs below the server's CPU priority.
//
// One body for every recurring pass: default a non-positive interval to a
// constant of its own, start a timer that fires at once, loop selecting on the
// context and the tick, run the pass, log, reset. Written out per pass, any
// change to how passes are scheduled — spreading goroutines that would
// otherwise wake together on a cold start, a measurement per pass, a first-run
// delay — is an edit per copy, and a missed copy diverges silently because
// nothing tests any of them.
//
// Reporting stays with the caller. Each pass logs a different thing: a count
// of what it collected, a count of what it sent and a count of what failed, a
// line per unit of work. A helper owning the logging would have to be told all
// of that, which is the call site written out again with a worse vocabulary.
//
// A worker taking queued work runs the same timer through Drain, which also
// holds the one rule the workers share: a failure that is only the process
// shutting down is not reported.
package background

import (
	"context"
	"time"
)

// Every runs pass on a timer until ctx is done.
//
// The first tick is immediate, because a process that has just started is the
// moment a sweep is most worth running: whatever accumulated while it was down
// is waiting.
//
// A non-positive interval takes fallback, so a caller may pass a configured
// value straight through without deciding what nothing means.
//
// pass returns nothing. What it found and whether it failed are the caller's
// to report, and a pass that fails is not a reason to stop: the next one is
// along shortly and what it could not do is still there.
func Every(ctx context.Context, interval, fallback time.Duration, pass func(context.Context)) {
	if interval <= 0 {
		interval = fallback
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		pass(ctx)
		timer.Reset(interval)
	}
}

// Drain runs once on the timer Every keeps, as many times in a row as it
// reports more to do, so a backlog drains at the speed of the work rather
// than at the speed of the poll.
//
// A failure ends the pass and is handed to failed, unless the context has
// ended: work cut short by shutdown is handed back and taken again later,
// which is no fault in the work or in the process. What succeeded is once's
// to report, since each worker reports a different thing.
func Drain(ctx context.Context, interval, fallback time.Duration,
	once func(context.Context) (more bool, err error), failed func(error)) {

	Every(ctx, interval, fallback, func(ctx context.Context) {
		for {
			more, err := once(ctx)
			if err != nil {
				if ctx.Err() == nil {
					failed(err)
				}
				return
			}
			if !more {
				return
			}
		}
	})
}
