// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import "time"

// NearestRank is the percentile position, for the test.
//
// Exported for the test alone: the figures it feeds are reachable only through
// a ninety-day window of decisions, and a table of durations is what shows the
// position the formula picks.
func NearestRank(sorted []time.Duration, part float64) time.Duration {
	return nearestRank(sorted, part)
}
