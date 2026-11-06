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

func TestTheListAcrossProductsOnADayHoldsWhatWasOpenThatDay(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		closedOnADay(t, f)
		today := time.Now().UTC().Truncate(24 * time.Hour)
		between := today.Add(-4 * 24 * time.Hour)
		who := f.holding(t, access.PublicTriage)
		_, total, err := f.store.Anywhere(t.Context(), who, 50, 0, finding.Filter{OpenOn: &between})
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 {
			t.Errorf("%d open across products on the day, want both", total)
		}
	})
}

func TestTheListOnADayBeneathAComponentHoldsWhatARescanReplaced(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		f.applied(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
		// The library moves, closing both.
		moved := at(libnl.Name, "3.9.0")
		f.shipped(t, through(moved))
		f.applied(t)
		today := time.Now().UTC().Truncate(24 * time.Hour)
		if _, err := f.db.NewUpdate().Table("finding").Set(`"opened_at" = ?`, today.Add(-5*24*time.Hour)).
			Set(`"closed_at" = ?`, today.Add(-3*24*time.Hour)).
			Where(`"build_id" = ?`, f.build).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		between := today.Add(-4 * 24 * time.Hour)
		under := f.componentID(t, swss.Name)
		_, total, err := f.store.Groups(ctx, f.holding(t, access.PublicTriage), f.scope, 50, 0,
			finding.Filter{OpenOn: &between, Beneath: &under})
		if err != nil {
			t.Fatal(err)
		}
		if total != 2 {
			t.Errorf("%d open on the day beneath %s, want both on the library it replaced", total, swss.Name)
		}
	})
}

func TestTheListOnADayCountsNothingFixedSinceAsOverdue(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		closedOnADay(t, f)
		today := time.Now().UTC().Truncate(24 * time.Hour)
		// The one fixed three days ago was due yesterday.
		if _, err := f.db.NewUpdate().Table("finding").Set(`"due_at" = ?`, today.Add(-24*time.Hour)).
			Where(`"build_id" = ?`, f.build).Where(`"closed_at" IS NOT NULL`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		between := today.Add(-4 * 24 * time.Hour)
		who := f.holding(t, access.PublicTriage)
		for name, filter := range map[string]finding.Filter{
			"overdue":    {OpenOn: &between, Overdue: true},
			"due before": {OpenOn: &between, DueBefore: new(today)},
		} {
			_, total, err := f.store.Groups(ctx, who, f.wholeProduct(), 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if total != 0 {
				t.Errorf("%s: %d, want none: the late one was fixed before its deadline", name, total)
			}
			_, across, err := f.store.Anywhere(ctx, who, 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if across != 0 {
				t.Errorf("%s across products: %d, want none", name, across)
			}
			components, err := f.store.CountComponentGroups(ctx, who, f.wholeProduct(), filter)
			if err != nil {
				t.Fatal(err)
			}
			if components != 0 {
				t.Errorf("%s by component: %d, want none", name, components)
			}
			_, listed, err := f.store.ComponentGroups(ctx, who, f.wholeProduct(), 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if listed != 0 {
				t.Errorf("%s component list: %d, want none", name, listed)
			}
			_, bumps, err := f.store.PlannedUpgrades(ctx, who, f.wholeProduct(), 50, 0, filter)
			if err != nil {
				t.Fatal(err)
			}
			if bumps != 0 {
				t.Errorf("%s bumps: %d, want none", name, bumps)
			}
		}
	})
}

func TestTheHiddenCountAndTheBumpsOnADayHoldWhatWasOpenThatDay(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		closedOnADay(t, f)
		today := time.Now().UTC().Truncate(24 * time.Hour)
		between, before := today.Add(-4*24*time.Hour), today.Add(-6*24*time.Hour)
		who := f.holding(t, access.PublicTriage)
		// Both are high, so a line at critical hides both that were open then.
		line := finding.MinimumSeverity{Word: "critical"}
		hidden, err := f.store.Hidden(ctx, who, f.wholeProduct(), finding.Filter{OpenOn: &between, MinimumSeverity: line})
		if err != nil {
			t.Fatal(err)
		}
		if hidden != 2 {
			t.Errorf("hiding %d on the day, want the two open then", hidden)
		}
		// Before either opened there is nothing to bump.
		_, bumps, err := f.store.PlannedUpgrades(ctx, who, f.wholeProduct(), 50, 0, finding.Filter{OpenOn: &before})
		if err != nil {
			t.Fatal(err)
		}
		if bumps != 0 {
			t.Errorf("%d bumps before anything opened, want none", bumps)
		}
	})
}
