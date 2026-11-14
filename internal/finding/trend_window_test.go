// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestATrendWindowOutOfRangeIsRefused(t *testing.T) {
	day := 24 * time.Hour
	for name, c := range map[string]struct {
		step  time.Duration
		steps int
		ok    bool
	}{
		"no steps":           {day, 0, false},
		"too many steps":     {day, finding.MostTrendSteps + 1, false},
		"the most steps":     {day, finding.MostTrendSteps, true},
		"a step of nothing":  {0, 12, false},
		"a step past a year": {finding.MostTrendStep + time.Hour, 1, false},
		"a week of steps":    {7 * day, 12, true},
	} {
		if err := finding.TrendWindow(c.step, c.steps); (err == nil) != c.ok {
			t.Errorf("%s: answered %v; want accepted %v", name, err, c.ok)
		}
	}
}
