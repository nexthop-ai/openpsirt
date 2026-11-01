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

func TestATrendBeneathAComponentFollowsItAcrossAVersionARescanReplaced(t *testing.T) {
	// A finding keeps the component it opened on, so the issues on libnl 3.7.0
	// sit on a component the build no longer holds once a rescan moves it to
	// 3.9.0. The chart beneath the library, asked at its present version, and
	// beneath teamd above it, counts them by name: open before the bump, the
	// one the bump fixed resolved at it, and the one it carried open throughout.
	// Beneath lldpd, which reaches no version of libnl, it counts none of them.
	each(t, func(t *testing.T, f *fixture) {
		now := time.Now().UTC()
		f.shipped(t, withLone(twoConsumers()))
		first := f.run(t)
		f.seenAt(t, first, now.Add(-20*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.build, first, []finding.Reported{
			found("CVE-2026-FIXED", libnl), found("CVE-2026-CARRIED", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, withLone(movedTo(libnlNew)))
		second := f.run(t)
		f.seenAt(t, second, now.Add(-10*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.build, second, []finding.Reported{
			found("CVE-2026-CARRIED", libnlNew),
		}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage)
		since := now.Add(-30 * 24 * time.Hour)
		for _, name := range []string{"libnl-3-200", "teamd"} {
			t.Run(name, func(t *testing.T) {
				under, err := f.graph.ComponentAs(t.Context(), f.build, name, graph.Choice{})
				if err != nil {
					t.Fatal(err)
				}
				points, err := f.store.Trend(t.Context(), who, f.wholeProduct(), since,
					24*time.Hour, 30, finding.Within{Beneath: &under})
				if err != nil {
					t.Fatal(err)
				}
				// Day 15 ends five days before the bump, and the last day ten
				// days after it.
				if got := points[14].Open; got != 2 {
					t.Errorf("%d open beneath %s before the bump, want both issues on the version it replaced",
						got, name)
				}
				if got := points[len(points)-1].Open; got != 1 {
					t.Errorf("%d open beneath %s after the bump, want the issue it carried", got, name)
				}
				var opened, resolved int
				for _, point := range points {
					opened += point.Opened
					resolved += point.Resolved
				}
				if opened != 2 {
					t.Errorf("%d opened beneath %s, want the two issues the first scan found", opened, name)
				}
				if resolved != 1 {
					t.Errorf("%d resolved beneath %s, want the issue the bump fixed", resolved, name)
				}
			})
		}

		under, err := f.graph.ComponentAs(t.Context(), f.build, lone.Name, graph.Choice{})
		if err != nil {
			t.Fatal(err)
		}
		points, err := f.store.Trend(t.Context(), who, f.wholeProduct(), since,
			24*time.Hour, 30, finding.Within{Beneath: &under})
		if err != nil {
			t.Fatal(err)
		}
		for _, point := range points {
			if point.Open != 0 || point.Opened != 0 || point.Resolved != 0 {
				t.Fatalf("beneath %s, which reaches no libnl, a day counts %d open, %d opened and %d resolved",
					lone.Name, point.Open, point.Opened, point.Resolved)
			}
		}
	})
}

// lone is a component the root pulls in that pulls in nothing.
var lone = at("lldpd", "1.0.18")

// withLone is snap with lone pulled in by the root.
func withLone(snap graph.Snapshot) graph.Snapshot {
	snap.Components = append(snap.Components, lone)
	snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: snap.Root, Child: lone})
	return snap
}

func TestAFlawRecordedOnAVersionARescanReplacedStaysBeneathItsName(t *testing.T) {
	// A flaw recorded by hand stays open on the component it was recorded
	// on: no scan closes it. Once a rescan moves libnl to 3.9.0 it sits on a
	// component the build no longer holds, and the tree's count beneath each
	// consumer, the list that count opens and the trend beside it still
	// carry it.
	each(t, func(t *testing.T, f *fixture) {
		f.store.Clock(minting)
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), nil); err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		if _, _, err := f.store.Enter(t.Context(), who, finding.Entering{
			BuildIDs: []int64{f.build}, Component: libnl.Name, Severity: "high",
			Summary: "The netlink parser reads past the end of a short message.",
		}); err != nil {
			t.Fatal(err)
		}
		replaced := f.componentID(t, libnl.Name)
		f.shipped(t, movedTo(libnlNew))
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), nil); err != nil {
			t.Fatal(err)
		}
		// The premise: the flaw is open at both occurrences, on 3.7.0.
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("%d findings are open after the rescan, want the flaw at its two occurrences", len(open))
		}
		for _, row := range open {
			if row.ComponentID != replaced {
				t.Fatalf("the flaw sits on component %d after the rescan, want %d, the version it replaced",
					row.ComponentID, replaced)
			}
		}

		_, kids, err := f.graph.Roots(t.Context(), who, f.build)
		if err != nil {
			t.Fatal(err)
		}
		if len(kids) != 2 {
			t.Fatalf("the root pulls in %d components, want libswsscommon and teamd", len(kids))
		}
		for _, kid := range kids {
			if kid.Beneath != 1 {
				t.Errorf("the tree counts %d beneath %s, want the flaw on the version the rescan replaced",
					kid.Beneath, kid.Name)
			}
			under := kid.ComponentID
			_, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{Beneath: &under})
			if err != nil {
				t.Fatal(err)
			}
			if total != 1 {
				t.Errorf("the list beneath %s holds %d, want the flaw its count names", kid.Name, total)
			}
			points, err := f.store.Trend(t.Context(), who, f.scope, minting().Add(-7*24*time.Hour),
				24*time.Hour, 7, finding.Within{Beneath: &under})
			if err != nil {
				t.Fatal(err)
			}
			if got := points[len(points)-1].Open; got != 1 {
				t.Errorf("the trend beneath %s counts %d open, want the flaw", kid.Name, got)
			}
		}
	})
}

func TestAVersionTheBuildHoldsAgainIsBeneathOnlyWhereItSits(t *testing.T) {
	// libnl 3.7.0 leaves the build and comes back under libswsscommon alone,
	// while teamd keeps 3.9.0. A version the build holds is no replaced one,
	// so beneath teamd counts the issue on 3.9.0 and not the one on 3.7.0.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), nil); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, movedTo(libnlNew))
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), nil); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{swss, teamd, libnl, libnlNew},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: swss}, {Parent: root, Child: teamd},
				{Parent: swss, Child: libnl}, {Parent: teamd, Child: libnlNew},
			},
		})
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{
			found("CVE-2026-OLD", libnl), found("CVE-2026-NEW", libnlNew),
		}); err != nil {
			t.Fatal(err)
		}

		under, err := f.graph.ComponentAs(t.Context(), f.build, teamd.Name, graph.Choice{})
		if err != nil {
			t.Fatal(err)
		}
		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), f.wholeProduct(),
			time.Now().UTC().Add(-7*24*time.Hour), 24*time.Hour, 8, finding.Within{Beneath: &under})
		if err != nil {
			t.Fatal(err)
		}
		if got := points[len(points)-1].Open; got != 1 {
			t.Errorf("%d open beneath teamd, want the issue on the 3.9.0 it pulls in", got)
		}
	})
}

func TestARuleBeneathAComponentPlacesAFlawOnAVersionARescanReplaced(t *testing.T) {
	// A flaw recorded on libnl 3.7.0 and held by nobody stays on 3.7.0 once a
	// rescan moves libnl to 3.9.0. A rule beneath teamd, written after, matches
	// it in its preview and places it in its sweep, as the tree's count
	// beneath teamd carries it. A rule beneath lldpd, which reaches no libnl,
	// matches nothing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, withLone(twoConsumers()))
		if _, err := f.store.Apply(ctx, f.build, f.run(t), nil); err != nil {
			t.Fatal(err)
		}
		who := f.planner(t, access.PublicTriage, access.PrivateTriage, access.Assigner)
		if _, _, err := f.store.Enter(ctx, who, finding.Entering{
			BuildIDs: []int64{f.build}, Component: libnl.Name, Severity: "high",
			Summary: "The netlink parser reads past the end of a short message.",
		}); err != nil {
			t.Fatal(err)
		}
		replaced := f.componentID(t, libnl.Name)
		f.shipped(t, withLone(movedTo(libnlNew)))
		if _, err := f.store.Apply(ctx, f.build, f.run(t), nil); err != nil {
			t.Fatal(err)
		}
		for _, row := range f.open(t) {
			if row.ComponentID != replaced {
				t.Fatalf("the flaw sits on component %d after the rescan, want %d, the version it replaced",
					row.ComponentID, replaced)
			}
		}

		caught, err := f.store.WouldMatch(ctx, who, f.productID, "", lone.Name, 20)
		if err != nil {
			t.Fatal(err)
		}
		if caught.Work != 0 {
			t.Errorf("a rule beneath %s matches %d pieces of work, want none", lone.Name, caught.Work)
		}
		caught, err = f.store.WouldMatch(ctx, who, f.productID, "", teamd.Name, 20)
		if err != nil {
			t.Fatal(err)
		}
		if caught.Work != 1 || caught.Unheld != 1 {
			t.Errorf("a rule beneath teamd matches %d pieces of work, %d unheld, want the flaw",
				caught.Work, caught.Unheld)
		}
		if _, err := f.store.AddRule(ctx, who, f.productID, f.team(t, "netlink"), "netlink", "",
			teamd.Name); err != nil {
			t.Fatal(err)
		}
		placed, _, _, err := f.store.ApplyRules(ctx, f.productID, 100)
		if err != nil {
			t.Fatal(err)
		}
		if placed != 2 {
			t.Errorf("the rule beneath teamd placed %d rows, want the flaw at its two occurrences", placed)
		}
	})
}
