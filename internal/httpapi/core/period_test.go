// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// A wait is said in days rounded to a tenth, never cut to one: cut, a median
// of 0.99 days reads as 0.9 and 1.96 as 1.9.
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
		if got := core.InDays(c.wait); got != c.want {
			t.Errorf("%v is %v days, want %v", c.wait, got, c.want)
		}
	}
}
