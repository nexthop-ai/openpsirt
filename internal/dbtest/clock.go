// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"sync"
	"time"
)

// Clock is a test clock for a pass or store that takes one: it starts at the
// real time and moves only when advanced.
//
// Rows a constructor stamps from the wall clock, such as an issue's first
// sighting, sit beside what the clock reads, so a window measured from it
// holds them on any day the suite runs. A clock fixed at a literal date
// drifts away from those stamps as the calendar moves, and a test built on
// it starts failing on a date nobody chose.
type Clock struct {
	mu sync.Mutex
	at time.Time
}

// NewClock is a clock reading the real time now, at the precision every
// engine stores.
func NewClock() *Clock {
	return &Clock{at: time.Now().UTC().Truncate(time.Microsecond)}
}

// Now is what the clock reads.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

// Advance moves the clock on by d.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}
