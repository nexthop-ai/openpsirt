// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"maps"
	"testing"

	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// image is a container image as SONiC describes one: a CycloneDX container
// whose package identifier carries the build stamp as its version.
func image(name, version string) graph.Described {
	return graph.Described{
		Purl:      "pkg:oci/" + name + "@" + version + "?arch=amd64",
		Name:      name,
		Version:   version,
		Container: true,
	}
}

// imaged is the product shipping one image, which holds openssl and curl.
func imaged(swss graph.Described) graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{swss, openssl, curl},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss},
			{Parent: swss, Child: curl},
			{Parent: swss, Child: openssl},
			{Parent: curl, Child: openssl},
		},
	}
}

// versions is every version row the build holds, oldest first.
func versions(t *testing.T, f *fixture) []graph.ImageVersion {
	t.Helper()
	var rows []graph.ImageVersion
	if err := f.db.DB.NewSelect().Model(&rows).
		Join(`JOIN "graph_node" AS "n" ON "n"."id" = "iv"."node_id"`).
		Where(`"n"."target_id" = ?`, f.targetID).
		Order("iv.id").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestWhatNamesAContainerImage(t *testing.T) {
	for _, c := range []struct {
		described graph.Described
		image     bool
	}{
		// SONiC: a CycloneDX container with an oci identifier.
		{image("docker-swss", "master.123-abc"), true},
		// Trivy and Syft: a digest as the version, the repository a
		// qualifier.
		{graph.Described{Name: "ubuntu",
			Purl: "pkg:oci/ubuntu@sha256%3A6042?arch=amd64&repository_url=index.docker.io%2Flibrary%2Fubuntu"}, true},
		// The docker type, which names an image the same way.
		{graph.Described{Name: "debian", Purl: "pkg:docker/library/debian@sha256%3A244f"}, true},
		// Capitals in the type are the type.
		{graph.Described{Name: "x", Purl: "pkg:OCI/x@1"}, true},
		// An SPDX package whose purpose is a container, with no identifier.
		{graph.Described{Name: "alpine", Version: "3.20", Container: true}, true},
		// An identifier of another type decides, whatever the format says.
		{graph.Described{Name: "x", Purl: "pkg:generic/x@1", Container: true}, false},
		{graph.Described{Name: "openssl", Purl: "pkg:deb/debian/openssl@3.0.11"}, false},
		{graph.Described{Name: "openssl", Version: "3.0.11"}, false},
	} {
		if got := c.described.IsImage(); got != c.image {
			t.Errorf("%+v: image %v, want %v", c.described, got, c.image)
		}
	}
}

func TestAnImageIsStoredWithoutItsVersion(t *testing.T) {
	for _, c := range []struct{ stated, stored string }{
		{"pkg:oci/docker-swss@master.123-abc?arch=amd64", "pkg:oci/docker-swss?arch=amd64"},
		{"pkg:oci/ubuntu@sha256%3A6042#sub", "pkg:oci/ubuntu#sub"},
		{"pkg:docker/library/debian@sha256:244f", "pkg:docker/library/debian"},
		{"pkg:oci/unversioned?tag=3.20", "pkg:oci/unversioned?tag=3.20"},
		{"pkg:oci/at@1?x=a@b", "pkg:oci/at?x=a@b"},
	} {
		got := graph.Described{Name: "x", Version: "1", Purl: c.stated}.AsImage()
		if got.Purl != c.stored || got.Version != "" {
			t.Errorf("%s is stored as %q at %q, want %q with no version", c.stated, got.Purl, got.Version, c.stored)
		}
	}
	a := image("docker-swss", "master.1-aaa").AsImage()
	b := image("docker-swss", "master.2-bbb").AsImage()
	if a.Identity() != b.Identity() {
		t.Error("one image rebuilt at two build stamps is two components")
	}
}

func TestARebuiltImageKeepsItsNodeAndEdgesAndRecordsTheVersion(t *testing.T) {
	// The product rebuilds its images in CI, and each build stamps them
	// anew with nothing inside moved. The node, every edge and every finding
	// beneath the image stay as they are; the version the build stated is
	// the one thing that moved, and it is recorded.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first, err := fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), imaged(image("docker-swss", "master.1-aaa")))
		if err != nil {
			t.Fatal(err)
		}
		if first.VersionsOpened != 1 || first.VersionsClosed != 0 {
			t.Errorf("a first build recorded %+v, want one version opened", first)
		}
		nodes, err := f.store.CurrentNodes(ctx, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		before := rowCounts(t, f)

		applied, err := fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), imaged(image("docker-swss", "master.2-bbb")))
		if err != nil {
			t.Fatal(err)
		}
		if applied.NodesOpened != 0 || applied.NodesClosed != 0 ||
			applied.EdgesOpened != 0 || applied.EdgesClosed != 0 {
			t.Errorf("a rebuilt image moved the graph: %+v", applied)
		}
		if applied.VersionsOpened != 1 || applied.VersionsClosed != 1 {
			t.Errorf("a rebuilt image recorded %+v, want one version closed and one opened", applied)
		}
		after := rowCounts(t, f)
		before["image_version"]++
		if !maps.Equal(after, before) {
			t.Errorf("rows went from %v to %v, want one more image version and nothing else", before, after)
		}
		again, err := f.store.CurrentNodes(ctx, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[int64]bool{}
		for _, n := range nodes {
			ids[n.ID] = true
		}
		for _, n := range again {
			if !ids[n.ID] {
				t.Errorf("node %d is new after a rebuild that moved only the image's version", n.ID)
			}
		}

		rows := versions(t, f)
		if len(rows) != 2 {
			t.Fatalf("%d version rows, want 2", len(rows))
		}
		if rows[0].Version != "master.1-aaa" || rows[0].ClosedScanID == nil ||
			rows[1].Version != "master.2-bbb" || rows[1].ClosedScanID != nil ||
			rows[1].Purl != "pkg:oci/docker-swss@master.2-bbb?arch=amd64" ||
			rows[0].NodeID != rows[1].NodeID {
			t.Errorf("the versions read %+v", rows)
		}

		// The same build again writes nothing.
		applied, err = fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), imaged(image("docker-swss", "master.2-bbb")))
		if err != nil {
			t.Fatal(err)
		}
		if applied != (graph.Applied{}) {
			t.Errorf("an identical rebuild wrote %+v", applied)
		}
	})
}

func TestAPackageMovingInsideARebuiltImageStillMoves(t *testing.T) {
	// Packages keep their versions in their identity, so an upgrade inside
	// an image closes the old node and opens the new one as it always did.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), imaged(image("docker-swss", "master.1-aaa"))); err != nil {
			t.Fatal(err)
		}
		moved := imaged(image("docker-swss", "master.2-bbb"))
		newer := at("curl", "8.5.0")
		moved.Components[2] = newer
		moved.Dependencies[1].Child = newer
		moved.Dependencies[3].Parent = newer
		applied, err := fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), moved)
		if err != nil {
			t.Fatal(err)
		}
		if applied.NodesOpened != 1 || applied.NodesClosed != 1 ||
			applied.EdgesOpened != 2 || applied.EdgesClosed != 2 ||
			applied.VersionsOpened != 1 || applied.VersionsClosed != 1 {
			t.Errorf("curl moving inside a rebuilt image wrote %+v, want its node and two edges moved "+
				"and the image's version", applied)
		}
	})
}

func TestTwoImagesOfOneNameInOneBuildKeepTheirVersions(t *testing.T) {
	// One component is one node in a build, so two images a build states
	// side by side under one name cannot both be the name. apko describes
	// every layer of an image as an image of one name, and a vendored
	// image can sit beside its own base. Each keeps its version in its
	// identity, as every package does, and records no version of its own.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		a, b := image("layer", "sha256:aaa"), image("layer", "sha256:bbb")
		snap := graph.Snapshot{
			Root:       root,
			Components: []graph.Described{a, b, openssl},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: a}, {Parent: root, Child: b},
				{Parent: a, Child: openssl},
			},
		}
		applied, err := fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), snap)
		if err != nil {
			t.Fatal(err)
		}
		if applied.NodesOpened != 4 || applied.VersionsOpened != 0 {
			t.Errorf("two layers of one name wrote %+v, want four nodes and no image versions", applied)
		}
		held, err := f.store.CurrentComponents(ctx, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		stamped := 0
		for _, c := range held {
			if c.Name == "layer" && c.Version != "" {
				stamped++
			}
		}
		if stamped != 2 {
			t.Errorf("%d of the two layers kept their version: %+v", stamped, held)
		}

		// The next build states the name once: it is the name from then on,
		// and its version is recorded.
		alone := graph.Snapshot{
			Root: root, Components: []graph.Described{a, openssl},
			Dependencies: []graph.Dependency{{Parent: root, Child: a}, {Parent: a, Child: openssl}},
		}
		applied, err = fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), alone)
		if err != nil {
			t.Fatal(err)
		}
		if applied.VersionsOpened != 1 {
			t.Errorf("one layer alone recorded %+v, want its version", applied)
		}
	})
}

func TestAnImageThatLeavesClosesItsVersion(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), imaged(image("docker-swss", "master.1-aaa"))); err != nil {
			t.Fatal(err)
		}
		applied, err := fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), tree())
		if err != nil {
			t.Fatal(err)
		}
		if applied.VersionsClosed != 1 || applied.NodesClosed != 1 {
			t.Errorf("an image leaving wrote %+v, want its node and its version closed", applied)
		}
		for _, row := range versions(t, f) {
			if row.ClosedScanID == nil {
				t.Errorf("version %q is still open for an image the build no longer ships", row.Version)
			}
		}
	})
}

func TestTheScannerIsGivenAnImageAsStored(t *testing.T) {
	// The scanner's report is matched back to a component by identity, so
	// what it is given is the component as stored: the image's name and its
	// identifier without a version.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		if _, err := fixtures.ApplyGraph(ctx, f.db, f.targetID, f.scan(t), imaged(image("docker-swss", "master.1-aaa"))); err != nil {
			t.Fatal(err)
		}
		held, err := f.store.CurrentComponents(ctx, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range held {
			if c.Name != "docker-swss" {
				continue
			}
			if c.Version != "" || c.Purl != "pkg:oci/docker-swss?arch=amd64" {
				t.Errorf("the scanner is given %+v", c)
			}
			if c.Identity() != image("docker-swss", "master.9-zzz").AsImage().Identity() {
				t.Error("what the scanner is given is not the stored image")
			}
			return
		}
		t.Fatal("the image is not among what the build holds")
	})
}
