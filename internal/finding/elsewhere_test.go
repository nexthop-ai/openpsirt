package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestAnotherBuildReachedFromTwoPlacesIsOneEntry(t *testing.T) {
	// A judgment is about an issue in a component, which is a group of places
	// rather than one, and a build it already reaches is one thing to be told
	// about however many of those places reach it.
	//
	// Keyed on the place rather than on the build, the same other build was
	// listed once per consumer that pulls the package in — so a kernel flaw at
	// sixty places drew sixty entries about one build, and what the screen
	// leads with was a count of this build's own graph rather than of builds
	// the judgment travels to.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		// Two consumers here and the same two there, at the same version: the
		// other build is reached by matching, from both places.
		f.shipped(t, twoConsumers())
		elsewhere := f.anotherBranch(t, "2026.06")
		f.shippedTo(t, elsewhere, twoConsumers())

		reported := []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-4", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}}
		if _, err := f.store.Apply(ctx, f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		there, err := f.store.Begin(ctx, finding.Run{
			TargetID: elsewhere, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-08-28", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(ctx, elsewhere, there.ID, reported); err != nil {
			t.Fatal(err)
		}

		open := f.open(t)
		if len(open) < 2 {
			t.Fatalf("%d findings opened here, want a place per consumer", len(open))
		}
		who := f.planner(t, access.PublicRead, access.PublicTriage)
		places, err := f.store.PlacesFor(ctx, who, f.target,
			open[0].VulnerabilityID, open[0].ComponentID)
		if err != nil {
			t.Fatal(err)
		}
		if len(places) < 2 {
			t.Fatalf("the finding resolves to %d places, want one per consumer", len(places))
		}

		reach, err := f.store.ReachingAcross(ctx, who, places, f.target)
		if err != nil {
			t.Fatal(err)
		}
		if len(reach.Automatic) != 1 {
			t.Fatalf("one other build reached from two places came back as %d entries: %+v",
				len(reach.Automatic), reach.Automatic)
		}
		// And it carries the places of both, which is what merging means.
		if reach.Automatic[0].Places < 2 {
			t.Errorf("the merged entry names %d places, want the places of both consumers",
				reach.Automatic[0].Places)
		}
	})
}
