// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// TrendWeeks is the window a trend draws where none is asked.
const TrendWeeks = 12

// Steps is a trend's window: a number of weeks or of days, ending at the coming
// midnight UTC, so a step holds whole days and is dated by its last one.
type Steps struct {
	Weeks int `query:"weeks" minimum:"1" maximum:"104" doc:"The number of weekly steps. Twelve where neither this nor days is sent"`
	Days  int `query:"days" minimum:"1" maximum:"730" doc:"The number of daily steps, in place of weeks. Sending both is refused"`
}

// Window is the start, the step and the number of steps. Both counts in one
// request are refused, because a caller who sent both meant one of them.
func (s Steps) Window(now time.Time) (since time.Time, step time.Duration, steps int, err error) {
	switch {
	case s.Weeks > 0 && s.Days > 0:
		return since, 0, 0, huma.Error422UnprocessableEntity(
			"weeks and days are two ways of saying how long a step is: send one")
	case s.Days > 0:
		step, steps = 24*time.Hour, s.Days
	case s.Weeks > 0:
		step, steps = 7*24*time.Hour, s.Weeks
	default:
		step, steps = 7*24*time.Hour, TrendWeeks
	}
	until := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	return until.Add(-time.Duration(steps) * step), step, steps, nil
}

// Stated is the window as a file's preamble says it.
func (s Steps) Stated() Stated {
	if s.Days > 0 {
		return Stated{Label: "days", Value: strconv.Itoa(s.Days)}
	}
	weeks := s.Weeks
	if weeks <= 0 {
		weeks = TrendWeeks
	}
	return Stated{Label: "weeks", Value: strconv.Itoa(weeks)}
}

// StepEnding is the heading a file's step column carries.
func (s Steps) StepEnding() string {
	if s.Days > 0 {
		return "day"
	}
	return "week ending"
}

// LastDay is the day a step ending at a midnight ends on.
func LastDay(end time.Time) string {
	return end.Add(-time.Nanosecond).UTC().Format(time.DateOnly)
}
