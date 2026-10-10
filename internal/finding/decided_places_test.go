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

// The decision counts read from the decision side: the product page's
// totals, built once over every decided place, and a page of the state
// filter, built for the page's own issues.

func TestTheOverviewCountsADecidedPlaceOnceHoweverManyDecisionsReachIt(t *testing.T) {
	// "Agreed" compares the places a standing decision covers against the
	// places there are. Two decisions at one place are one decided place:
	// counted as two they equal the two places, and an issue half answered
	// reads as agreed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		places := f.placesOf(t, "CVE-2026-1")
		if len(places) != 2 {
			t.Fatalf("the fixture put the issue at %d places, want 2", len(places))
		}
		by := f.somebodyElse(t)
		reader := f.holding(t, access.PublicRead)
		stands := func() finding.BuildStanding {
			t.Helper()
			builds, whole, err := f.store.HowItStands(ctx, reader, f.productID)
			if err != nil {
				t.Fatal(err)
			}
			for _, build := range builds {
				if build.TargetID == f.target && (build.Agreed != whole.Agreed || build.Undecided != whole.Undecided) {
					t.Errorf("the build reads agreed %d, undecided %d where the product reads %d and %d",
						build.Agreed, build.Undecided, whole.Agreed, whole.Undecided)
				}
			}
			return whole
		}
		if got := stands(); got.Open != 1 || got.Undecided != 1 || got.Agreed != 0 {
			t.Fatalf("before any decision: open %d, undecided %d, agreed %d; want 1, 1, 0",
				got.Open, got.Undecided, got.Agreed)
		}

		under := places[swss.Name]
		f.decidedAt(t, by, under, "approved", libnl.Version, swss.Version, "first-key")
		f.decidedAt(t, by, under, "approved", libnl.Version, swss.Version, "second-key")
		if got := stands(); got.Undecided != 0 || got.Agreed != 0 {
			t.Errorf("two decisions at one of two places: undecided %d, agreed %d; want 0 and 0",
				got.Undecided, got.Agreed)
		}

		f.decidedAt(t, by, places[teamd.Name], "approved", libnl.Version, teamd.Version, "third-key")
		if got := stands(); got.Agreed != 1 {
			t.Errorf("a decision at every place: agreed %d, want 1", got.Agreed)
		}
	})
}

func TestTheOverviewCountsADecisionOnlyAtTheVersionItWasMadeAgainst(t *testing.T) {
	// A live claim covers a place at the versions it was keyed on. One made
	// against another version of the library says nothing about this one, so
	// the issue is still undecided here.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		places := f.placesOf(t, "CVE-2026-1")
		f.decidedAt(t, f.somebodyElse(t), places[swss.Name], "approved", libnlNew.Version, swss.Version, "elsewhere")
		_, whole, err := f.store.HowItStands(ctx, f.holding(t, access.PublicRead), f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if whole.Undecided != 1 || whole.Agreed != 0 {
			t.Errorf("a decision about %s at a place holding %s: undecided %d, agreed %d; want 1 and 0",
				libnlNew.Version, libnl.Version, whole.Undecided, whole.Agreed)
		}
	})
}

func TestEachRowOfALapsedPageSaysItLapsed(t *testing.T) {
	// The page reads what it shows about its rows from decisions about the
	// page's own issues alone. Every row of every page still says the word
	// the filter found it by.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		issues := []string{"CVE-2026-1", "CVE-2026-2", "CVE-2026-3"}
		reported := make([]finding.Reported, 0, len(issues))
		for _, issue := range issues {
			reported = append(reported, found(issue, libnl))
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		by := f.somebodyElse(t)
		// Two lapsed and one agreed, so the page has rows it must leave out.
		f.decidedAt(t, by, f.placesOf(t, "CVE-2026-1")[swss.Name], "lapsed", libnl.Version, swss.Version, "")
		f.decidedAt(t, by, f.placesOf(t, "CVE-2026-2")[swss.Name], "lapsed", libnl.Version, swss.Version, "")
		f.decidedAt(t, by, f.placesOf(t, "CVE-2026-3")[swss.Name], "approved", libnl.Version, swss.Version, "agreed")

		reader := f.holding(t, access.PublicTriage)
		lapsed := finding.Filter{States: []finding.ClaimStanding{finding.StandingLapsed}}
		for _, page := range []struct {
			what string
			read func(offset int) ([]finding.Group, int, error)
		}{
			{"one product", func(offset int) ([]finding.Group, int, error) {
				return f.store.Groups(ctx, reader, f.scope, 1, offset, lapsed)
			}},
			{"every product", func(offset int) ([]finding.Group, int, error) {
				return f.store.Anywhere(ctx, reader, 1, offset, lapsed)
			}},
		} {
			seen := map[string]bool{}
			for offset := 0; offset < 3; offset++ {
				groups, total, err := page.read(offset)
				if err != nil {
					t.Fatal(err)
				}
				if total != 2 {
					t.Errorf("%s: %d lapsed, want 2", page.what, total)
				}
				for _, group := range groups {
					seen[group.Vulnerability] = true
					if group.State != finding.StandingLapsed {
						t.Errorf("%s: %s on page %d reads as %q, want lapsed",
							page.what, group.Vulnerability, offset, group.State)
					}
				}
			}
			if len(seen) != 2 || !seen["CVE-2026-1"] || !seen["CVE-2026-2"] {
				t.Errorf("%s: the pages held %v, want the two lapsed issues", page.what, seen)
			}
		}
	})
}

func TestTheOverviewAgreesAGroupInTwoBuildsOnlyWhereEveryPlaceInBothIsAnswered(t *testing.T) {
	// The product's totals fold the build rows by issue and component, so the
	// decided places of a group in two builds are added together before they
	// are compared with its places. One decision at a place both builds hold
	// answers both places, so the issue is agreed in each build and in the
	// product; the second issue is undecided in all three.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, through(libnl))
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		by := f.somebodyElse(t)
		f.decidedAt(t, by, f.placesOf(t, "CVE-2026-1")[swss.Name], "approved", libnl.Version, swss.Version, "both")
		builds, whole, err := f.store.HowItStands(ctx, f.holding(t, access.PublicRead), f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 2 {
			t.Fatalf("%d build rows, want 2", len(builds))
		}
		for _, build := range builds {
			if build.Open != 2 || build.Agreed != 1 || build.Undecided != 1 {
				t.Errorf("build %d: open %d, agreed %d, undecided %d; want 2, 1, 1",
					build.TargetID, build.Open, build.Agreed, build.Undecided)
			}
		}
		if whole.Open != 2 || whole.Agreed != 1 || whole.Undecided != 1 {
			t.Errorf("the product: open %d, agreed %d, undecided %d; want 2, 1, 1",
				whole.Open, whole.Agreed, whole.Undecided)
		}
	})
}

func TestTheOverviewFoldsAGroupAnsweredInOneBuildAndOverdueInTheOther(t *testing.T) {
	// One issue at one component in two builds, under a different consumer in
	// each, so the two builds hold two places of one group. The first build's
	// place is answered and not yet due; the second's is unanswered and past
	// its deadline. Each build row says its own half. The product's group is
	// open and overdue, because its earliest deadline has passed, and neither
	// undecided nor agreed, because one place is answered and the other is
	// not. Whatever order the rows arrive in, a fold reading one build's row
	// alone, or the later deadline, answers otherwise.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		other := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, other, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{teamd, libnl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: teamd},
				{Parent: teamd, Child: libnl},
			},
		})
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		for target, due := range map[int64]time.Time{
			f.target: now.AddDate(0, 0, 30),
			other:    now.AddDate(0, 0, -100),
		} {
			if _, err := f.db.DB.NewUpdate().TableExpr(`"finding"`).
				Set("due_at = ?", due).Where("target_id = ?", target).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		f.decidedAt(t, f.somebodyElse(t), f.placesOf(t, "CVE-2026-1")[swss.Name],
			"approved", libnl.Version, swss.Version, "first-build")

		builds, whole, err := f.store.HowItStands(ctx, f.holding(t, access.PublicRead), f.productID)
		if err != nil {
			t.Fatal(err)
		}
		want := map[int64][4]int{f.target: {1, 0, 0, 1}, other: {1, 1, 1, 0}}
		if len(builds) != len(want) {
			t.Fatalf("%d build rows, want %d", len(builds), len(want))
		}
		for _, build := range builds {
			got := [4]int{build.Open, build.Overdue, build.Undecided, build.Agreed}
			if got != want[build.TargetID] {
				t.Errorf("build %d: open, overdue, undecided, agreed %v; want %v",
					build.TargetID, got, want[build.TargetID])
			}
		}
		if got := [4]int{whole.Open, whole.Overdue, whole.Undecided, whole.Agreed}; got != [4]int{1, 1, 0, 0} {
			t.Errorf("the product: open, overdue, undecided, agreed %v; want [1 1 0 0]", got)
		}
	})
}
