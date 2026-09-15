package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestATrendOverReleasesHasOnePointPerReleaseOldestFirst(t *testing.T) {
	// A tag never moves, so what it shipped with is one frozen point — and
	// releases months apart on a calendar read as slow drift rather than
	// the step change they were.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// The fixture's own stream is a branch, so it must not appear.
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// Two tagged releases of the same product, one worse than the other.
		first := f.anotherBuild(t, "v1.0")
		f.shippedTo(t, first, through(libnl))
		if _, err := f.store.Apply(ctx, first, f.runOn(t, first), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		second := f.anotherBuild(t, "v1.1")
		f.shippedTo(t, second, through(libnl))
		if _, err := f.store.Apply(ctx, second, f.runOn(t, second), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}

		points, err := f.store.ReleaseTrend(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), 12)
		if err != nil {
			t.Fatal(err)
		}
		if len(points) != 2 {
			t.Fatalf("plotted %d points, want one per tagged release: %+v", len(points), points)
		}
		if points[0].Stream != "v1.0" || points[1].Stream != "v1.1" {
			t.Errorf("the releases are in the order %q, %q", points[0].Stream, points[1].Stream)
		}
		// Counted in issues, like the calendar trend, so two charts on one
		// screen cannot quote different units for the same word.
		if points[0].Open != 2 {
			t.Errorf("v1.0 reads %d open, want the 2 distinct issues", points[0].Open)
		}
		if points[1].Open != 1 {
			t.Errorf("v1.1 reads %d open, want 1", points[1].Open)
		}
	})
}

func TestABranchIsNotAPointOnAReleaseTrend(t *testing.T) {
	// A branch moves and is scanned nightly; it has no place on an axis whose
	// points are things that never move again.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, through(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		points, err := f.store.ReleaseTrend(ctx, f.holding(t, access.PublicRead),
			f.wholeProduct(), 12)
		if err != nil {
			t.Fatal(err)
		}
		if len(points) != 0 {
			t.Errorf("a branch was plotted as a release: %+v", points)
		}
	})
}

func TestAcrossProductsThereIsNoSequenceToPlot(t *testing.T) {
	// Two products' tags interleave by date and mean nothing side by side, so
	// this refuses rather than answering wrongly.
	//
	// Refused rather than answered empty: an empty list is what a product
	// with no releases looks like, so the two were one answer — and a
	// dashboard polling without a product read as a product that had never
	// cut a release.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		tag := f.anotherBuild(t, "v1.0")
		f.shippedTo(t, tag, through(libnl))
		if _, err := f.store.Apply(ctx, tag, f.runOn(t, tag), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		points, err := f.store.ReleaseTrend(ctx, f.holding(t, access.PublicRead),
			finding.Scope{}, 12)
		if !errors.Is(err, finding.ErrNoProductNamed) {
			t.Errorf("a release trend with no product named answered %v", err)
		}
		if len(points) != 0 {
			t.Errorf("a release trend was drawn with no product named: %+v", points)
		}
	})
}

func TestAScannedBuildWithNothingOpenIsStillAReleaseOfItsOwn(t *testing.T) {
	// A build with nothing open was absent from this list, and absent is how
	// the list says "never scanned". So a clean release read as an unmeasured
	// one — the opposite of what it is, and it was missing from the chart that
	// exists to show the estate getting better.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		dirty := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, dirty,
			[]finding.Reported{found("CVE-2026-DIRTY", libnl)}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), dirty, "0.100.0", "2026-09-05", "", nil); err != nil {
			t.Fatal(err)
		}

		// A second build of the same product, scanned, with nothing reported.
		clean := f.anotherVariant(t, "mellanox")
		f.shippedTo(t, clean, twoConsumers())
		run := f.runOn(t, clean)
		if _, err := f.store.Apply(t.Context(), clean, run, []finding.Reported{}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), run, "0.100.0", "2026-09-05", "", nil); err != nil {
			t.Fatal(err)
		}

		releases, err := f.store.Releases(t.Context(), f.holding(t, access.PrivateRead), f.productID)
		if err != nil {
			t.Fatal(err)
		}
		byVariant := map[string]finding.Release{}
		for _, r := range releases {
			byVariant[r.Variant] = r
		}
		if _, held := byVariant["mellanox"]; !held {
			t.Fatalf("a scanned build with nothing open is missing: %+v", releases)
		}
		if got := byVariant["mellanox"].Open; got != 0 {
			t.Errorf("the clean build reports %d open, want 0", got)
		}
		if got := byVariant["broadcom"].Open; got == 0 {
			t.Error("the build with a finding reports nothing open")
		}
	})
}
