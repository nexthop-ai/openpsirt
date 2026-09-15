// Package background runs a pass on a timer until its context ends.
//
// Every recurring pass in this tree held the same body: default a non-positive
// interval to a constant of its own, start a timer that fires at once, loop
// selecting on the context and the tick, run the pass, log, reset. Any change
// to how passes are scheduled — spreading goroutines that would otherwise wake
// together on a cold start, a measurement per pass, a first-run delay — was an
// edit per copy, and a missed copy would diverge silently because nothing
// tested any of them. Some had already diverged, over whether the log line
// carries the trace context.
//
// **Reporting stays with the caller.** Each pass logs a different thing: a
// count of what it collected, a count of what it sent and a count of what
// failed, a line per unit of work. A helper that owned the logging would have
// to be told all of that, which is the call site written out again with a
// worse vocabulary.
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
