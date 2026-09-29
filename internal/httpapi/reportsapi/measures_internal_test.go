// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// A wait is said in days rounded to a tenth, not cut to one. Cut, a median of
// 0.99 days read as 0.9 and 1.96 as 1.9.
func TestAWaitIsRoundedToATenthOfADay(t *testing.T) {
	day := 24 * time.Hour
	for _, c := range []struct {
		wait time.Duration
		want float64
	}{
		{time.Duration(0.99 * float64(day)), 1.0},
		{time.Duration(1.96 * float64(day)), 2.0},
		{time.Duration(1.94 * float64(day)), 1.9},
		{0, 0},
	} {
		if got := inDays(c.wait); got != c.want {
			t.Errorf("%v is %v days, want %v", c.wait, got, c.want)
		}
	}
}

// A moment is stated in UTC whatever zone the driver handed it back in.
func TestAMomentIsStatedInUTC(t *testing.T) {
	east := time.Date(2026, 9, 28, 19, 0, 0, 0, time.FixedZone("east", 5*3600))
	if got := core.Stamp(east); got != "2026-09-28T14:00:00Z" {
		t.Errorf("19:00 at +05:00 is stated as %s", got)
	}
	if got := core.Stamp(time.Time{}); got != "" {
		t.Errorf("no moment is stated as %q", got)
	}
}
