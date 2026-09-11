package finding_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestABumpThatFixedNothingIsNotCountedAsResolved(t *testing.T) {
	// Otherwise the two lines move together and say opposite things: work
	// completed, on the same chart where the same issue arrives as new.
	//
	// Counted as issues rather than places: the issue never leaves the set,
	// because its version moved and it came along, so nothing here needs a
	// rule about closure reasons to get the answer right.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		first := f.run(t)
		f.seenAt(t, first, time.Now().UTC().Add(-20*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, first,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// Bumped, and the scanner still reports it. The old rows close as
		// superseded and new ones open against the new version.
		f.shipped(t, movedTo(libnlNew))
		second := f.run(t)
		f.seenAt(t, second, time.Now().UTC().Add(-10*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, second,
			[]finding.Reported{found("CVE-2026-1", libnlNew)}); err != nil {
			t.Fatal(err)
		}

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			time.Now().UTC().Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		var resolved int
		for _, point := range points {
			resolved += point.Resolved
		}
		if resolved != 0 {
			t.Errorf("a bump that fixed nothing counted %d findings as resolved", resolved)
		}
		// One issue, however many places it sits at. It was two here when the
		// trend counted finding rows, and counting rows reported 441,108 open
		// on a real image where 5,661 issues were open.
		if points[len(points)-1].Open != 1 {
			t.Errorf("%d open at the end, want the one issue against the new version",
				points[len(points)-1].Open)
		}
	})
}

func TestAnUpgradeThatFixedSomethingIsCountedAsResolved(t *testing.T) {
	// The other side of the same rule, so that excluding superseded does not
	// quietly become excluding everything.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		first := f.run(t)
		f.seenAt(t, first, time.Now().UTC().Add(-20*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, first,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// Bumped, and the scanner stops reporting it.
		f.shipped(t, movedTo(libnlNew))
		second := f.run(t)
		f.seenAt(t, second, time.Now().UTC().Add(-10*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, second, nil); err != nil {
			t.Fatal(err)
		}

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			time.Now().UTC().Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		var resolved int
		for _, point := range points {
			resolved += point.Resolved
		}
		// One issue went away, not two places. What somebody reads as work
		// completed is the issue.
		if resolved != 1 {
			t.Errorf("an upgrade that fixed it counted %d resolved, want 1", resolved)
		}
	})
}

func TestATrendCountsNothingFromOutsideTheRangeItDraws(t *testing.T) {
	// The answer, not the cost. The statement also refuses to *read* what
	// cannot be in range — a finding closed before the first point, or opened
	// after the last — but that is about how much is fetched and is not
	// visible in what comes back, so nothing here can assert it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		old := f.run(t)
		f.seenAt(t, old, time.Now().UTC().Add(-400*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, old,
			[]finding.Reported{found("CVE-2026-ANCIENT", libnl)}); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, movedTo(libnlNew))
		closing := f.run(t)
		f.seenAt(t, closing, time.Now().UTC().Add(-380*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, closing, nil); err != nil {
			t.Fatal(err)
		}

		// A fortnight's window, a year after all of that ended.
		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			time.Now().UTC().Add(-14*24*time.Hour), 24*time.Hour, 14, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		for _, point := range points {
			if point.Open != 0 || point.Opened != 0 || point.Resolved != 0 {
				t.Fatalf("a point in the last fortnight counted %d open, %d new, %d resolved "+
					"from a year ago", point.Open, point.Opened, point.Resolved)
			}
		}
	})
}

func TestATrendWithNoStepStillDrawsARange(t *testing.T) {
	// The step arrives as a query parameter and the loop walks whatever it
	// says, so zero would draw one instant however many times.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-20*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			time.Time{}, 0, 4, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if len(points) != 4 {
			t.Fatalf("%d points, want 4", len(points))
		}
		for i := 1; i < len(points); i++ {
			if !points[i].At.After(points[i-1].At) {
				t.Fatalf("point %d is at %v, the same instant or earlier than point %d",
					i, points[i].At, i-1)
			}
		}
	})
}

func TestATrendCanBeAskedForOnePartOfTheTree(t *testing.T) {
	// A team owns an area rather than a product, and the three lines answered
	// only for a whole one. The findings list has narrowed by a component and
	// by a subtree from the start; this is the chart beside it taking the same
	// two narrowings, so the two cannot come to disagree about what a subtree
	// is.
	//
	// The fixture's shape is what makes it a real test: swss and teamd both
	// depend on libnl, so an issue under swss is one under teamd as well, and
	// a subtree that answered by name alone would count what sits outside it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		f.seenAt(t, run, time.Now().UTC().Add(-20*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, run, []finding.Reported{
			found("CVE-2026-1", libnl),
			found("CVE-2026-2", teamd),
		}); err != nil {
			t.Fatal(err)
		}

		since := time.Now().UTC().Add(-30 * 24 * time.Hour)
		who := f.holding(t, access.PublicTriage)
		last := func(t *testing.T, within finding.Within) finding.Point {
			t.Helper()
			points, err := f.store.Trend(t.Context(), who, f.wholeProduct(), since,
				24*time.Hour, 30, within)
			if err != nil {
				t.Fatal(err)
			}
			if len(points) == 0 {
				t.Fatal("the trend drew no points")
			}
			return points[len(points)-1]
		}

		// Both issues, unnarrowed.
		if got := last(t, finding.Within{}).Open; got != 2 {
			t.Errorf("%d open across the product, want both issues", got)
		}
		// Under libswsscommon sits libnl and nothing else, so the issue filed against
		// teamd is outside it.
		if got := last(t, finding.Within{Beneath: "libswsscommon"}).Open; got != 1 {
			t.Errorf("%d open beneath libswsscommon, want the one that sits under it", got)
		}
		// And under teamd sits libnl as well, so that one is in both.
		if got := last(t, finding.Within{Beneath: "teamd"}).Open; got != 2 {
			t.Errorf("%d open beneath teamd, want the one on it and the one under it", got)
		}
		// A name is the component itself at any version, not its subtree.
		if got := last(t, finding.Within{Component: "libnl-3-200"}).Open; got != 1 {
			t.Errorf("%d open against libnl-3-200 by name, want the one filed there", got)
		}
	})
}

func TestASubtreeTrendIsRefusedWhereTheSelectionIsNotOneBuild(t *testing.T) {
	// A subtree is a walk over one build's edges. Answered from whichever
	// build sorted first it would be a chart of somewhere else; answered from
	// a component identifier left at zero it would be an empty one. Both are
	// silent, so it refuses.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// A second build under the same product, so the selection holds two.
		f.anotherBuild(t, "v2")

		_, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), f.wholeProduct(),
			time.Now().UTC().Add(-30*24*time.Hour), 24*time.Hour, 30,
			finding.Within{Beneath: "libswsscommon"})
		if err == nil {
			t.Fatal("a subtree trend across two builds was answered rather than refused")
		}
		if !strings.Contains(err.Error(), "one build") {
			t.Errorf("the refusal does not say why: %v", err)
		}
	})
}

func TestAScannerGoingQuietIsNotCountedAsWorkDone(t *testing.T) {
	// An issue that stops being reported with the component present and
	// unchanged is a fault to investigate, not a fix — so it leaves the open
	// set without being counted as resolved, and the step it left in is the
	// step it actually left in.
	//
	// Which step that is used to be found by walking every bucket looking for
	// the one the moment fell in, once per step, for every row: the answer was
	// right and it cost steps squared per row to get. The arithmetic that
	// replaced it has to land in the same bucket, which is what this pins.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		now := time.Now().UTC()
		run := f.run(t)
		f.seenAt(t, run, now.Add(-20*24*time.Hour))
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// Gone, with nothing to say why, inside the window.
		gone := now.Add(-5 * 24 * time.Hour)
		f.closeIt(t, "CVE-2026-1", finding.Unexplained, gone)

		since := now.Add(-30 * 24 * time.Hour)
		step := 24 * time.Hour
		points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
			since, step, 30, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		var resolved int
		for _, point := range points {
			resolved += point.Resolved
		}
		if resolved != 0 {
			t.Errorf("a scanner going quiet counted %d findings as resolved", resolved)
		}
		// And it is in the open set while it was reported and out of it from
		// the step it disappeared in — which is the bucket the arithmetic has
		// to land on. A step is the interval ending at the moment it names, so
		// a finding closed exactly at a point's moment is gone by that point
		// and one opened exactly at it is present.
		opened := now.Add(-20 * 24 * time.Hour)
		for i, point := range points {
			want := 0
			if !point.At.Before(opened) && point.At.Before(gone) {
				want = 1
			}
			if point.Open != want {
				t.Errorf("step %d (%s) says %d open, want %d",
					i, point.At.Format(time.RFC3339), point.Open, want)
			}
		}
	})
}
