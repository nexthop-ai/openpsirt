// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
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

func TestTheComponentPageListsTheVersionsEachBuildStampedAnImageWith(t *testing.T) {
	// The image is one component however often it is rebuilt, so the page
	// for it lists what each build stamped it with, newest first, and a
	// package inside it lists none.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, inImage(swssImage("master.1-aaa"), libnl))
		f.shipped(t, inImage(swssImage("master.2-bbb"), libnl))
		reader := f.holding(t, access.PublicTriage)
		builds, err := f.store.AcrossBuilds(ctx, reader, f.wholeProduct(), "docker-swss")
		if err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 || len(builds[0].Packages) != 1 {
			t.Fatalf("the image answers %+v, want one build and one package", builds)
		}
		image := builds[0].Packages[0]
		if image.Version != "" {
			t.Errorf("the image answers at version %q, want none of its own", image.Version)
		}
		stated := image.Stated
		if len(stated) != 2 || stated[0].Version != "master.2-bbb" || stated[0].Until != nil ||
			stated[1].Version != "master.1-aaa" || stated[1].Until == nil ||
			!stated[1].Until.Equal(stated[0].From) ||
			stated[0].Purl != "pkg:oci/docker-swss@master.2-bbb?arch=amd64" {
			t.Errorf("the image's versions read %+v, want the second build's open and first", stated)
		}

		inside, err := f.store.AcrossBuilds(ctx, reader, f.wholeProduct(), libnl.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(inside) != 1 || len(inside[0].Packages) != 1 || inside[0].Packages[0].Stated != nil {
			t.Errorf("a package inside the image answers %+v, want no stated versions", inside)
		}
	})
}

// acmeImage is a supplier's container image as one build stamps it.
func acmeImage(stamp string) graph.Described {
	return graph.Described{
		Purl: "pkg:oci/docker-acme@" + stamp + "?arch=amd64", Name: "docker-acme",
		Version: stamp, Container: true,
	}
}

// underTheImage is the latest row for zlib inside the image.
func (f *fixture) underTheImage(t *testing.T) finding.Finding {
	t.Helper()
	var latest finding.Finding
	for _, row := range f.every(t) {
		if placedAt(t, f, []finding.Finding{row})["zlib under docker-acme"].ID == row.ID {
			latest = row
		}
	}
	if latest.ID == 0 {
		t.Fatal("nothing sits beneath the image")
	}
	return latest
}

func TestAClaimNamingAnImageAtAStampAnswersOnlyTheBuildStatingThatStamp(t *testing.T) {
	// The image is stored with no version, and the claim names the one the
	// build stamped. It is placed against the stamp the build states now.
	each(t, func(t *testing.T, f *fixture) {
		claim := insideOf(sbom.NotAffected, acmeImage("master.2-bbb"), "never called")
		f.shipped(t, beside(acmeImage("master.2-bbb")))
		f.argues(t, claim)
		f.reported(t, found(inside, zlib))
		if row := f.underTheImage(t); row.SuppressedBy == nil {
			t.Error("a claim about zlib inside the image at the stamp the build states answers nothing")
		}

		f.shipped(t, beside(acmeImage("master.3-ccc")))
		f.argues(t, claim)
		f.reported(t, found(inside, zlib))
		if row := f.underTheImage(t); row.SuppressedBy != nil {
			t.Error("a claim about the image at master.2 answers the build stamping it master.3")
		}
	})
}

func TestASuppliersStatementNamingAnImageAtAStampClosesOnlyUnderThatStamp(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		image := acmeImage("master.2-bbb")
		claim := sbom.Suppression{
			Vulnerability: inside, Status: sbom.NotAffected,
			Justification: "vulnerable_code_not_in_execute_path",
			Statement:     "zlib's inflate is never reached",
		}
		f.publishes(t, []finding.Statement{finding.StatementOf(claim, sbom.Target{
			Purl: zlib.Purl, Name: zlib.Name, Within: &sbom.Target{Purl: image.Purl, Name: image.Name},
		})}, "sha256:acme-image")
		f.shipped(t, beside(image))
		f.reported(t, found(inside, zlib))
		if row := f.underTheImage(t); row.ClosedBecause != finding.Disclaimed {
			t.Errorf("zlib inside the image the statement names closed as %q, want disclaimed", row.ClosedBecause)
		}

		f.shipped(t, beside(acmeImage("master.3-ccc")))
		f.reported(t, found(inside, zlib))
		if row := f.underTheImage(t); row.ClosedAt != nil {
			t.Errorf("zlib inside the image at the next stamp closed as %q, want it open", row.ClosedBecause)
		}
	})
}
