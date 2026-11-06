// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// rootOnly is an inventory that lost every component: a broken build.
func rootOnly() graph.Snapshot { return graph.Snapshot{Root: root} }

// scannedAt stores snap, runs a scan started at when, and applies what it
// reported.
func (f *fixture) scannedAt(t *testing.T, snap graph.Snapshot, when time.Time, reported ...finding.Reported) {
	t.Helper()
	f.shipped(t, snap)
	run := f.run(t)
	f.seenAt(t, run, when)
	if _, err := f.store.Apply(t.Context(), f.build, run, reported); err != nil {
		t.Fatal(err)
	}
}

// totals is the sum of each flow over a trend.
type totals struct{ open, opened, corrected, returned, baseline, firstScans int }

func summed(points []finding.Point) totals {
	var out totals
	for _, p := range points {
		out.opened += p.New
		out.corrected += p.Corrected
		out.returned += p.Returned
		out.baseline += p.Baseline
		out.firstScans += p.FirstScans
	}
	if len(points) > 0 {
		out.open = points[len(points)-1].Open
	}
	return out
}

// stepHolding is the index of the step a moment falls in.
func stepHolding(points []finding.Point, at time.Time) int {
	for i, p := range points {
		if !p.At.Before(at) {
			return i
		}
	}
	return -1
}

func TestAnIssueThatLeavesAndComesBackIsReturnedNotCorrectedAndNew(t *testing.T) {
	// A broken inventory drops every component for one scan and the next
	// restores them. The issue is one identity, so the bounce is one return,
	// and the closure it reverses is no fix.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, twoConsumers(), now.Add(-20*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, rootOnly(), now.Add(-10*24*time.Hour))
		back := now.Add(-9 * 24 * time.Hour)
		f.scannedAt(t, twoConsumers(), back, found("CVE-2026-1", libnl))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		got := summed(points)
		if got != (totals{open: 1, returned: 1, baseline: 1, firstScans: 1}) {
			t.Errorf("a bounce counted %+v, want one baseline, one return and nothing corrected or new", got)
		}
		if i := stepHolding(points, back); points[i].Returned != 1 {
			t.Errorf("the return is not in the step it came back in: step %d says %d", i, points[i].Returned)
		}
	})
}

func TestAnIssueAfterTheFirstScanIsNewAndTheFirstScanIsBaseline(t *testing.T) {
	// The first scan is the inventory arriving: its issues are a baseline
	// beside the step, never a bar of new work.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		first := now.Add(-20 * 24 * time.Hour)
		f.scannedAt(t, twoConsumers(), first, found("CVE-2026-1", libnl))
		later := now.Add(-10 * 24 * time.Hour)
		f.scannedAt(t, twoConsumers(), later, found("CVE-2026-1", libnl), found("CVE-2026-2", teamd))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := summed(points); got != (totals{open: 2, opened: 1, baseline: 1, firstScans: 1}) {
			t.Errorf("counted %+v, want the first scan's issue as baseline and the later one as new", got)
		}
		if i := stepHolding(points, first); points[i].Baseline != 1 || points[i].FirstScans != 1 {
			t.Errorf("step %d of the first scan says %d baseline over %d first scans, want 1 and 1",
				i, points[i].Baseline, points[i].FirstScans)
		}
		if i := stepHolding(points, later); points[i].New != 1 || points[i].NewBySeverity["high"] != 1 {
			t.Errorf("step %d of the later scan says %d new, %v by severity, want one high",
				i, points[i].New, points[i].NewBySeverity)
		}
	})
}

func TestAnIssueFixedBeforeTheWindowThatComesBackInItIsReturned(t *testing.T) {
	// The window does not reach the fix, so only the findings closed before
	// it say the issue was present once.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, twoConsumers(), now.Add(-60*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, rootOnly(), now.Add(-50*24*time.Hour))
		f.scannedAt(t, twoConsumers(), now.Add(-5*24*time.Hour), found("CVE-2026-1", libnl))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := summed(points); got != (totals{open: 1, returned: 1}) {
			t.Errorf("counted %+v, want the one issue as returned", got)
		}
	})
}

func TestTheFirstStepCountsWhatMovedInIt(t *testing.T) {
	// The first step differs from the window's start, so an issue arriving
	// in it is counted.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		since := now.Add(-30 * 24 * time.Hour)
		f.scannedAt(t, twoConsumers(), now.Add(-40*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, twoConsumers(), since.Add(time.Hour), found("CVE-2026-1", libnl), found("CVE-2026-2", teamd))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			since, 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if points[0].New != 1 {
			t.Errorf("the first step counts %d new, want the issue that arrived in it", points[0].New)
		}
	})
}

func TestAnIssueIsReturnedOnlyWhereTheReaderCanSeeItWasPresentBefore(t *testing.T) {
	// Present before is read like every count, with the reader's visibility:
	// an undisclosed finding closed before the window says nothing to somebody
	// who cannot read it, or returned and new tell them it existed.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, twoConsumers(), now.Add(-60*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, rootOnly(), now.Add(-50*24*time.Hour))
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"visibility" = ?`, access.Private).
			Where(`"closed_at" IS NOT NULL`).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.scannedAt(t, twoConsumers(), now.Add(-5*24*time.Hour), found("CVE-2026-1", libnl))

		for _, one := range []struct {
			roles []access.Role
			want  totals
		}{
			{[]access.Role{access.PublicTriage}, totals{open: 1, opened: 1}},
			{[]access.Role{access.PublicTriage, access.PrivateTriage}, totals{open: 1, returned: 1}},
		} {
			points, err := f.store.Trend(t.Context(), f.holding(t, one.roles...), finding.Scope{},
				now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
			if err != nil {
				t.Fatal(err)
			}
			if got := summed(points); got != one.want {
				t.Errorf("%v counted %+v, want %+v", one.roles, got, one.want)
			}
		}
	})
}
