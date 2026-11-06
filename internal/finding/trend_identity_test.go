// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
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
	// The upload arrives before the run that reads it, as it does outside a
	// test.
	if _, err := f.db.DB.NewUpdate().TableExpr(`"scan"`).Set(`"received_at" = ?`, when.Add(-time.Minute)).
		Where(`"id" = ?`, f.lastScan).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	run := f.run(t)
	f.seenAt(t, run, when)
	if _, err := f.store.Apply(t.Context(), f.build, run, reported); err != nil {
		t.Fatal(err)
	}
}

// widened is a graph with twelve more packages beneath the root, big enough
// that losing all of it passes the floor of names a sharp move needs. Without
// is the names left out.
func widened(without ...graph.Described) graph.Snapshot {
	snap := twoConsumers()
	for i := range 12 {
		filler := at(fmt.Sprintf("filler-%d", i), "1.0")
		snap.Components = append(snap.Components, filler)
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: filler})
	}
	for _, gone := range without {
		var kept []graph.Described
		for _, c := range snap.Components {
			if c != gone {
				kept = append(kept, c)
			}
		}
		snap.Components = kept
		var edges []graph.Dependency
		for _, e := range snap.Dependencies {
			if e.Child != gone && e.Parent != gone {
				edges = append(edges, e)
			}
		}
		snap.Dependencies = edges
	}
	return snap
}

// totals is the sum of each flow over a trend.
type totals struct{ open, opened, corrected, returned, restored, baseline, firstScans int }

func summed(points []finding.Point) totals {
	var out totals
	for _, p := range points {
		out.opened += p.New
		out.corrected += p.Corrected
		out.returned += p.Returned
		out.restored += p.Restored
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

func TestTheTrendCountsAnIssueAtEachComponentAndAVersionBumpKeepsTheComponent(t *testing.T) {
	// One issue in two packages is two; a bump fixing it in one is one
	// corrected; a bump carrying it in the other is the same component and no
	// flow.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		first := now.Add(-20 * 24 * time.Hour)
		f.scannedAt(t, twoConsumers(), first, found("CVE-2026-1", libnl), found("CVE-2026-1", teamd))
		bump := now.Add(-10 * 24 * time.Hour)
		f.scannedAt(t, bumpedLibnl(), bump, found("CVE-2026-1", teamd), found("CVE-2026-2", libnlNew))
		carried := now.Add(-5 * 24 * time.Hour)
		f.scannedAt(t, twoConsumers(), carried, found("CVE-2026-1", teamd), found("CVE-2026-2", libnl))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if i := stepHolding(points, first); points[i].Baseline != 2 || points[i].Open != 2 {
			t.Errorf("the first scan's step says %d baseline and %d open, want the issue at both components",
				points[i].Baseline, points[i].Open)
		}
		if i := stepHolding(points, bump); points[i].Corrected != 1 || points[i].New != 1 || points[i].Open != 2 {
			t.Errorf("the bump's step says %d corrected, %d new and %d open, want one fixed, one arrived, two open",
				points[i].Corrected, points[i].New, points[i].Open)
		}
		if i := stepHolding(points, carried); points[i].New != 0 || points[i].Corrected != 0 ||
			points[i].Returned != 0 || points[i].Open != 2 {
			t.Errorf("the step carrying an issue across a version says %+v, want two open and nothing moved",
				points[i])
		}
	})
}

func TestAnIssueBeforeTheWindowAtAnotherComponentIsNewAtThisOne(t *testing.T) {
	// Present before is asked of the issue at its component: the issue fixed
	// in one package before the window says nothing about another package.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, twoConsumers(), now.Add(-60*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, twoConsumers(), now.Add(-50*24*time.Hour))
		f.scannedAt(t, twoConsumers(), now.Add(-5*24*time.Hour), found("CVE-2026-1", teamd))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := summed(points); got != (totals{open: 1, opened: 1}) {
			t.Errorf("counted %+v, want the issue new at the package it had never been in", got)
		}
	})
}

func TestAReturnAfterASharpRemovalIsAMarkNotAReturnedBar(t *testing.T) {
	// An upload that lost the whole inventory moved a sharp share of it, so
	// what comes back after it is the inventory put right.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, widened(), now.Add(-20*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, rootOnly(), now.Add(-10*24*time.Hour))
		back := now.Add(-9 * 24 * time.Hour)
		f.scannedAt(t, widened(), back, found("CVE-2026-1", libnl))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := summed(points); got != (totals{open: 1, restored: 1, baseline: 1, firstScans: 1}) {
			t.Errorf("a return after a sharp removal counted %+v, want it restored and no returned bar", got)
		}
		if i := stepHolding(points, back); points[i].Restored != 1 || len(points[i].ReturnedBySeverity) != 0 {
			t.Errorf("step %d says %d restored and %v returned, want the mark alone",
				i, points[i].Restored, points[i].ReturnedBySeverity)
		}
	})
}

func TestAReturnAfterASmallRemovalIsAReturnedBar(t *testing.T) {
	// One package of fifteen leaving moves too little of the inventory to be
	// a broken upload, so its issue coming back is a return.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, widened(), now.Add(-20*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, widened(libnl), now.Add(-10*24*time.Hour))
		f.scannedAt(t, widened(), now.Add(-9*24*time.Hour), found("CVE-2026-1", libnl))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := summed(points); got != (totals{open: 1, returned: 1, baseline: 1, firstScans: 1}) {
			t.Errorf("a return after a small removal counted %+v, want one returned bar", got)
		}
	})
}

func TestAReturnAfterASharpRemovalBeforeTheWindowIsAMark(t *testing.T) {
	// The removal is before the window, so only the closure read before it
	// says what took the issue out.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, widened(), now.Add(-60*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, rootOnly(), now.Add(-50*24*time.Hour))
		f.scannedAt(t, widened(), now.Add(-5*24*time.Hour), found("CVE-2026-1", libnl))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := summed(points); got != (totals{open: 1, restored: 1}) {
			t.Errorf("counted %+v, want the one issue restored", got)
		}
	})
}

// bumped is widened with every filler and libnl at another version.
func bumped() graph.Snapshot {
	snap := widened(libnl)
	for i, c := range snap.Components {
		if len(c.Name) > 7 && c.Name[:7] == "filler-" {
			moved := at(c.Name, "2.0")
			snap.Components[i] = moved
			for j, e := range snap.Dependencies {
				if e.Child == c {
					snap.Dependencies[j].Child = moved
				}
			}
		}
	}
	snap.Components = append(snap.Components, libnlNew)
	snap.Dependencies = append(snap.Dependencies,
		graph.Dependency{Parent: swss, Child: libnlNew}, graph.Dependency{Parent: teamd, Child: libnlNew})
	return snap
}

func TestAReturnAfterASharpUploadThatUpgradedIsAReturnedBar(t *testing.T) {
	// Only a removal is the inventory going missing. An upload that moved
	// most of a build by upgrading it fixed the issue, and its coming back
	// with a downgrade is a return.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, widened(), now.Add(-20*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, bumped(), now.Add(-10*24*time.Hour))
		f.scannedAt(t, widened(), now.Add(-9*24*time.Hour), found("CVE-2026-1", libnl))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := summed(points); got.returned != 1 || got.restored != 0 {
			t.Errorf("a return after a sharp upgrade counted %+v, want one returned bar", got)
		}
	})
}

func TestAReturnIsJudgedByTheRemovalThatLastTookItOut(t *testing.T) {
	// A sharp removal long ago says nothing about the small one since.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.scannedAt(t, widened(), now.Add(-25*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, rootOnly(), now.Add(-20*24*time.Hour))
		f.scannedAt(t, widened(), now.Add(-15*24*time.Hour), found("CVE-2026-1", libnl))
		f.scannedAt(t, widened(libnl), now.Add(-10*24*time.Hour))
		f.scannedAt(t, widened(), now.Add(-5*24*time.Hour), found("CVE-2026-1", libnl))

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := summed(points); got.returned != 1 || got.restored != 1 {
			t.Errorf("counted %+v, want the first return restored and the second returned", got)
		}
	})
}

// inventoryReads counts the statements that read a build's graph.
type inventoryReads struct{ n atomic.Int64 }

func (c *inventoryReads) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	if strings.Contains(e.Query, `"graph_node"`) {
		c.n.Add(1)
	}
	return ctx
}

func (c *inventoryReads) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestRemovalsNoReturnFollowsAreNeverWorkedOut(t *testing.T) {
	// Whether an upload was sharp is worked out only for the closures a
	// return reverses, so a build that keeps dropping packages costs the
	// trend nothing more.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		fillers := []graph.Described{at("filler-0", "1.0"), at("filler-1", "1.0"), at("filler-2", "1.0")}
		reported := func(without ...graph.Described) []finding.Reported {
			out := []finding.Reported{found("CVE-2026-1", libnl)}
			for _, c := range fillers {
				if !slices.Contains(without, c) {
					out = append(out, found("CVE-2026-9", c))
				}
			}
			return out
		}
		f.scannedAt(t, widened(), now.Add(-25*24*time.Hour), reported()...)
		f.scannedAt(t, rootOnly(), now.Add(-20*24*time.Hour))
		f.scannedAt(t, widened(), now.Add(-15*24*time.Hour), reported()...)

		reads := &inventoryReads{}
		store := finding.NewStore(dbtest.Hooked(f.db, reads).DB)
		read := func() (totals, int64) {
			reads.n.Store(0)
			points, err := store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
				now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
			if err != nil {
				t.Fatal(err)
			}
			return summed(points), reads.n.Load()
		}
		bounced, before := read()
		if bounced.restored != 4 {
			t.Fatalf("the bounce counted %+v, want its four issues at components restored", bounced)
		}

		for i := range fillers {
			f.scannedAt(t, widened(fillers[:i+1]...), now.Add(-time.Duration(10-2*i)*24*time.Hour),
				reported(fillers[:i+1]...)...)
		}
		got, after := read()
		if got.restored != 4 || got.corrected != 3 || got.returned != 0 {
			t.Errorf("counted %+v, want the four restored and the three removed packages corrected", got)
		}
		if after != before {
			t.Errorf("three removals no return follows took the graph reads from %d to %d", before, after)
		}
	})
}
