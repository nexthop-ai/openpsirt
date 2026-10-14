// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// swssImage is the image libnl ships in, as SONiC stamps it at one build.
func swssImage(stamp string) graph.Described {
	return graph.Described{
		Purl: "pkg:oci/docker-swss@" + stamp + "?arch=amd64", Name: "docker-swss",
		Version: stamp, Container: true,
	}
}

// inImage is the product shipping one image holding the library given.
func inImage(image, library graph.Described) graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{image, library},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: image},
			{Parent: image, Child: library},
		},
	}
}

// agreedHere is how the product stands, read by somebody who may read it.
func (f *fixture) agreedHere(t *testing.T) finding.BuildStanding {
	t.Helper()
	_, whole, err := f.store.HowItStands(t.Context(), f.holding(t, access.PublicRead), f.productID)
	if err != nil {
		t.Fatal(err)
	}
	return whole
}

func TestARebuiltImageClosesNothingBeneathItAndKeepsItsDecisions(t *testing.T) {
	// The same build uploaded twice, the image's build stamp the only
	// difference. Nothing beneath the image closes or opens, the graph
	// keeps every node and edge, one version is recorded, and the decision
	// made beneath the image still answers the finding.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		reported := []finding.Reported{found("CVE-2026-1", libnl)}
		f.shipped(t, inImage(swssImage("master.1-aaa"), libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		place := f.placesOf(t, "CVE-2026-1")["docker-swss"]
		if place.ID == 0 {
			t.Fatal("libnl is not open beneath the image")
		}
		// Keyed as a proposal is: the image is the consumer, at the version
		// its component carries, which is none.
		f.decidedAt(t, f.somebodyElse(t), place, "approved", libnl.Version, "", "beneath-the-image")
		if got := f.agreedHere(t); got.Agreed != 1 {
			t.Fatalf("before the rebuild: agreed %d, want 1", got.Agreed)
		}
		rows := f.every(t)

		scan := f.lastScan
		f.shipped(t, inImage(swssImage("master.2-bbb"), libnl))
		if f.lastScan == scan {
			t.Fatal("the rebuild was not recorded")
		}
		applied, err := f.store.Apply(ctx, f.target, f.run(t), reported)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 0 || applied.Closed != 0 {
			t.Errorf("a rebuilt image opened %d and closed %d findings beneath it, want none",
				applied.Opened, applied.Closed)
		}
		after := f.every(t)
		if len(after) != len(rows) {
			t.Errorf("%d finding rows after the rebuild, %d before", len(after), len(rows))
		}
		for _, row := range after {
			if row.ClosedAt != nil {
				t.Errorf("finding %d closed on a rebuild that moved only the image's version", row.ID)
			}
		}
		if got := f.agreedHere(t); got.Agreed != 1 || got.Undecided != 0 {
			t.Errorf("after the rebuild: agreed %d, undecided %d; want the decision still standing",
				got.Agreed, got.Undecided)
		}
		var stated []graph.ImageVersion
		if err := f.db.DB.NewSelect().Model(&stated).Order("iv.id").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(stated) != 2 || stated[0].Version != "master.1-aaa" || stated[1].Version != "master.2-bbb" ||
			stated[0].ClosedScanID == nil || *stated[0].ClosedScanID != f.lastScan {
			t.Errorf("the image's versions read %+v, want the first closed by the rebuild and the second open",
				stated)
		}
	})
}

func TestAPackageMovingInsideARebuiltImageSupersedesItsFinding(t *testing.T) {
	// Packages keep their versions in their identity. An upgrade inside the
	// image closes the finding against the old version, opens it against the
	// new one, and a decision made about the old version no longer answers it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, inImage(swssImage("master.1-aaa"), libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		place := f.placesOf(t, "CVE-2026-1")["docker-swss"]
		f.decidedAt(t, f.somebodyElse(t), place, "approved", libnl.Version, "", "beneath-the-image")

		f.shipped(t, inImage(swssImage("master.2-bbb"), libnlNew))
		applied, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{found("CVE-2026-1", libnlNew)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 1 || applied.Closed != 1 {
			t.Errorf("libnl moving opened %d and closed %d, want one of each", applied.Opened, applied.Closed)
		}
		for _, row := range f.every(t) {
			if row.ClosedAt != nil && row.ClosedBecause != finding.Superseded {
				t.Errorf("the finding against the old version closed as %v, want superseded", row.ClosedBecause)
			}
		}
		if got := f.agreedHere(t); got.Agreed != 0 || got.Undecided != 1 {
			t.Errorf("after the upgrade: agreed %d, undecided %d; want the old decision answering nothing",
				got.Agreed, got.Undecided)
		}
	})
}
