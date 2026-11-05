// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestTheListOnADayHoldsWhatWasOpenThatDay(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
		// The next scan no longer reports CVE-2026-2, closing it.
		f.applied(t, found("CVE-2026-1", libnl))
		day := func(n int) time.Time {
			return time.Now().UTC().Truncate(24 * time.Hour).Add(time.Duration(n) * 24 * time.Hour)
		}
		if _, err := f.db.NewUpdate().Table("finding").Set(`"opened_at" = ?`, day(-5).Add(6*time.Hour)).
			Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.NewUpdate().Table("finding").Set(`"closed_at" = ?`, day(-3).Add(6*time.Hour)).
			Where(`"build_id" = ?`, f.build).Where(`"closed_at" IS NOT NULL`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)
		for _, asked := range []struct {
			name string
			on   *time.Time
			want int
		}{
			{"now", nil, 1},
			{"while both were open", new(day(-4)), 2},
			{"the day one closed", new(day(-3)), 2},
			{"the day after it closed", new(day(-2)), 1},
			{"the day both opened", new(day(-5)), 2},
			{"before either opened", new(day(-6)), 0},
		} {
			filter := finding.Filter{OpenOn: asked.on}
			groups, total, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if total != asked.want || len(groups) != asked.want {
				t.Errorf("%s: a total of %d and a page of %d, want %d", asked.name, total, len(groups), asked.want)
			}
			// Both issues sit on one component, so the view by component is
			// one row while either was open.
			components, err := f.store.CountComponentGroups(ctx, who, f.wholeProduct(), filter)
			if err != nil {
				t.Fatal(err)
			}
			if want := min(asked.want, 1); components != want {
				t.Errorf("%s: %d components, want %d", asked.name, components, want)
			}
			if asked.want == 2 {
				byComponent, _, err := f.store.ComponentGroups(ctx, who, f.wholeProduct(), 50, 0, filter)
				if err != nil {
					t.Fatal(err)
				}
				if len(byComponent) != 1 {
					t.Errorf("%s: a page of %d components, want 1", asked.name, len(byComponent))
				}
			}
		}
	})
}

// closedOnADay is a build holding CVE-2026-1 open and CVE-2026-2 closed, both
// opened five days ago, the second closed three days ago, and the reader
// counting them on the day between.
func closedOnADay(t *testing.T, f *fixture) func(t *testing.T) int {
	t.Helper()
	ctx := t.Context()
	f.shipped(t, through(libnl))
	f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
	f.applied(t, found("CVE-2026-1", libnl))
	today := time.Now().UTC().Truncate(24 * time.Hour)
	if _, err := f.db.NewUpdate().Table("finding").Set(`"opened_at" = ?`, today.Add(-5*24*time.Hour)).
		Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.NewUpdate().Table("finding").Set(`"closed_at" = ?`, today.Add(-3*24*time.Hour)).
		Where(`"build_id" = ?`, f.build).Where(`"closed_at" IS NOT NULL`).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	who := f.holding(t, access.PublicTriage)
	between := today.Add(-4 * 24 * time.Hour)
	return func(t *testing.T) int {
		t.Helper()
		_, total, err := f.store.Groups(t.Context(), who, f.wholeProduct(), 50, 0, finding.Filter{OpenOn: &between})
		if err != nil {
			t.Fatal(err)
		}
		return total
	}
}

func TestTheListOnADayLeavesOutWhatWasNeverPresent(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		count := closedOnADay(t, f)
		if _, err := f.db.NewUpdate().Table("finding").Set(`"closed_because" = ?`, finding.Invalid).
			Where(`"build_id" = ?`, f.build).Where(`"closed_at" IS NOT NULL`).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := count(t); got != 1 {
			t.Errorf("%d open on the day, want 1: a record taken back was never open", got)
		}
	})
}

func TestTheListOnADayLeavesOutWhatOneRunRecordedClosed(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		count := closedOnADay(t, f)
		if _, err := f.db.NewUpdate().Table("finding").Set(`"opened_run_id" = "closed_run_id"`).
			Where(`"build_id" = ?`, f.build).Where(`"closed_at" IS NOT NULL`).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := count(t); got != 1 {
			t.Errorf("%d open on the day, want 1: a row first seen closed was never open", got)
		}
	})
}
