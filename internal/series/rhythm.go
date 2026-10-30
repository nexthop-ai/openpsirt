// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series

import (
	"slices"
	"time"
)

// The bounds on when a series has gone quiet on a build. One rule, read by
// the alert that a series stopped reporting and by the coverage figures, so
// a series the alert names is the one the page marks.
const (
	// rhythmRuns is how many applied runs a series needs on a build before
	// its rhythm is a thing to measure. Two runs are one gap, which is a
	// guess.
	rhythmRuns = 3
	// RhythmGaps is how many of the newest gaps the rhythm is read from, so a
	// pipeline that moved from weekly to nightly is judged by what it does
	// now. A reader asks for the newest RhythmGaps+1 arrivals.
	RhythmGaps = 10
	// quietTimes is how many usual gaps make one silence.
	quietTimes = 3
	// quietFloor is the shortest silence worth saying. A pipeline running
	// hourly that misses three runs is a bad afternoon rather than a
	// pipeline nobody is watching.
	quietFloor = 24 * time.Hour
)

// Rhythm is how a series arrives on one build: its usual gap, how long it
// has been silent, and whether that is longer than the rhythm allows.
type Rhythm struct {
	// Known is whether enough runs arrived to have a rhythm. A series with
	// fewer than three applied runs on a build is never quiet.
	Known bool
	// Usual is the median of the newest gaps between arrivals: the series'
	// own expected interval. Zero where the rhythm is not known.
	Usual time.Duration
	// Allowed is the silence the rhythm allows: three usual gaps, never
	// under a day.
	Allowed time.Duration
	// Silent is how long since the newest arrival.
	Silent time.Duration
	// Quiet is whether Silent is longer than Allowed.
	Quiet bool
}

// RhythmOf is the rhythm of a series on one build, from when its applied runs
// arrived, newest first, at most RhythmGaps+1 of them, as of now.
//
// The usual gap is the median, which a single long weekend or a burst of
// reruns does not move.
func RhythmOf(arrived []time.Time, now time.Time) Rhythm {
	if len(arrived) == 0 {
		return Rhythm{}
	}
	out := Rhythm{Silent: now.Sub(arrived[0])}
	if len(arrived) < rhythmRuns {
		return out
	}
	gaps := make([]time.Duration, 0, len(arrived)-1)
	for i := 1; i < len(arrived); i++ {
		gaps = append(gaps, arrived[i-1].Sub(arrived[i]))
	}
	slices.Sort(gaps)
	out.Usual = gaps[len(gaps)/2]
	if len(gaps)%2 == 0 {
		out.Usual = (gaps[len(gaps)/2-1] + gaps[len(gaps)/2]) / 2
	}
	out.Known = true
	out.Allowed = max(quietTimes*out.Usual, quietFloor)
	out.Quiet = out.Silent > out.Allowed
	return out
}

// Since is the rhythm judged against a silence counted from last instead of
// the newest arrival: a series whose runs arrive and prove nothing is as
// quiet as one whose runs stopped.
func (r Rhythm) Since(last, now time.Time) Rhythm {
	r.Silent = now.Sub(last)
	r.Quiet = r.Known && r.Silent > r.Allowed
	return r
}
