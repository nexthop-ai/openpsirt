package queue

import "time"

// SetClock replaces the queue's idea of now, for tests that decide when a
// claim has gone stale rather than waiting for it to.
func SetClock(q *Queue, now func() time.Time) {
	q.now = now
}

// SetLeaseClock replaces the leases' idea of now, for tests that decide when a
// lease has lapsed rather than waiting for it to.
func SetLeaseClock(l *Leases, now func() time.Time) {
	l.now = now
}

// SetLocking turns the claim's row locking off, for the test that demonstrates
// exclusivity does not rest on it.
//
// Here rather than on Options, because a switch that turns off the thing
// keeping workers out of each other's way is one nothing outside a test should
// be able to reach.
func SetLocking(q *Queue, on bool) {
	q.locking = on
}
