// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"testing"
	"time"
)

func TestAZeroDateMoreThanTenYearsAwayIsNotGiven(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		left int
		date bool
	}{
		// One done a day over the fourteen: 3,650 left is ten years exactly.
		{3650, true},
		{3651, false},
	} {
		points := make([]BurnPoint, ProjectionDays)
		for i := range points {
			points[i].Fixed = 1
		}
		points[len(points)-1].Left = c.left
		ahead := projected(points, now)
		if !ahead.Converging || (ahead.ZeroOn != nil) != c.date {
			t.Errorf("%d left at one a day projected %+v, want a date: %v", c.left, ahead, c.date)
		}
	}
}

func TestChosenPackagesSaysWhetherItChoseMore(t *testing.T) {
	for _, c := range []struct {
		packages int
		more     bool
	}{{mostMatched, false}, {mostMatched + 1, true}} {
		rows := make([]trendRow, c.packages)
		for i := range rows {
			rows[i].Component = string(rune('a' + i))
		}
		chosen, more := chosenPackages(rows, Within{Component: "x"})
		if len(chosen) != min(c.packages, mostMatched) || more != c.more {
			t.Errorf("%d packages chose %d, more %v; want %d, more %v",
				c.packages, len(chosen), more, min(c.packages, mostMatched), c.more)
		}
	}
}
