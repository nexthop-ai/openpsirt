// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core_test

import (
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// The edge's bounds on a trend's window are the store's, which refuses a
// window past them: a struct tag cannot name the constant, so this holds the
// two equal.
func TestATrendWindowTheEdgeAcceptsIsOneTheStoreWorksOut(t *testing.T) {
	steps := reflect.TypeFor[core.Steps]()
	for _, c := range []struct {
		field string
		step  time.Duration
	}{
		{"Days", 24 * time.Hour},
		{"Weeks", 7 * 24 * time.Hour},
	} {
		f, ok := steps.FieldByName(c.field)
		if !ok {
			t.Fatalf("Steps has no field %s", c.field)
		}
		most, err := strconv.Atoi(f.Tag.Get("maximum"))
		if err != nil {
			t.Fatalf("%s's maximum: %v", c.field, err)
		}
		if err := finding.TrendWindow(c.step, most); err != nil {
			t.Errorf("%s at its maximum, %d, is refused by the store: %v", c.field, most, err)
		}
		if time.Duration(most)*c.step < time.Duration(finding.MostTrendSteps-6)*24*time.Hour {
			t.Errorf("%s at its maximum, %d, reaches short of the store's %d days", c.field, most, finding.MostTrendSteps)
		}
	}
	if err := finding.TrendWindow(24*time.Hour, core.TrendWeeks); err != nil {
		t.Errorf("the default window is refused by the store: %v", err)
	}
}
