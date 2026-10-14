// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"bytes"
	"testing"
	"time"

	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// Each producer states a container image its own way, and each is read as an
// image. The root of a document is the product, stored by name already, and
// is not counted here.
func TestEachProducersContainerImageIsReadAsAnImage(t *testing.T) {
	for _, c := range []struct {
		fixture string
		how     string
		// images is how many components are images, and named how many of
		// them a build states once under their name, which is what is stored
		// by name.
		images, named int
	}{
		{"switch-image.cdx.json.xz", "CycloneDX container, oci identifier stamped with the build", 34, 34},
		{"image.cdx.json", "CycloneDX container, oci identifier at a digest", 2, 2},
		{"build-fragment.cdx.json", "CycloneDX container in a fragment with no root", 1, 1},
		{"acme-app.spdx3.json", "SPDX 3 package whose purpose is a container, no identifier", 1, 1},
		{"apko-wolfi-image.spdx.json", "SPDX 2 layers, every one an oci identifier named image", 11, 0},
		{"alpine-image.spdx.json", "SPDX 2 image as the document's root", 0, 0},
		{"trivy-ubuntu.cdx.json", "CycloneDX container as the document's root", 0, 0},
		{"snyk-juice-shop.cdx.json", "an application with no image in it", 0, 0},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			doc, err := sbom.Read(bytes.NewReader(fixtureBytes(t, c.fixture)), sbom.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			images := 0
			byName := map[string]int{}
			for _, d := range doc.Components {
				if d.IsImage() {
					images++
					byName[d.AsImage().Identity()]++
				}
			}
			named := 0
			for _, n := range byName {
				if n == 1 {
					named++
				}
			}
			if images != c.images || named != c.named {
				t.Errorf("%s: %d images, %d of them by name; want %d and %d", c.how, images, named,
					c.images, c.named)
			}
		})
	}
}

// A real switch image rebuilt with every image stamped anew and nothing inside
// moved: stored, it opens and closes no node and no edge, and records each
// image's new version.
func TestARebuiltSwitchImageMovesOnlyWhatItsImagesAreStampedWith(t *testing.T) {
	first := fixtureBytes(t, "switch-image.cdx.json.xz")
	const stamp = "sbom-consumer-metadata.0-5acba0313"
	if !bytes.Contains(first, []byte(stamp)) {
		t.Fatalf("the fixture carries no %s, so nothing is rebuilt", stamp)
	}
	rebuilt := bytes.ReplaceAll(first, []byte(stamp), []byte("sbom-consumer-metadata.1-0ddba11"))
	world.Each(t, func(t *testing.T, w *world.World) {
		ctx := t.Context()
		scans := ingest.NewStore(w.DB.DB)
		store := graph.NewStore(w.DB.DB)
		built := time.Now().UTC().Add(-24 * time.Hour)
		apply := func(body []byte, hash string, at time.Time) graph.Applied {
			t.Helper()
			doc, err := sbom.Read(bytes.NewReader(body), sbom.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			rec, outcome, err := scans.Record(ctx, ingest.Arriving{
				TargetID: w.Target.ID, ContentHash: hash, BuiltAt: at, ParserVersion: "test",
			})
			if err != nil || outcome != ingest.Accept {
				t.Fatalf("record: outcome %v, err %v", outcome, err)
			}
			applied, err := store.Apply(ctx, w.Target.ID, rec.ID, doc.Snapshot(graph.Described{Name: "sonic"}))
			if err != nil {
				t.Fatal(err)
			}
			return applied
		}
		if opened := apply(first, "first", built); opened.VersionsOpened != 34 {
			t.Errorf("the first build recorded %d image versions, want 34", opened.VersionsOpened)
		}
		got := apply(rebuilt, "second", built.Add(time.Hour))
		want := graph.Applied{VersionsOpened: 34, VersionsClosed: 34}
		if got != want {
			t.Errorf("the rebuild wrote %+v, want %+v", got, want)
		}
	})
}

// The format's own word is what names an image that carries no package
// identifier, in each format that has one. An identifier of another type is
// what the package is, whatever the format calls it.
func TestTheFormatNamesAnImageThatCarriesNoIdentifier(t *testing.T) {
	cyclonedx := `{"bomFormat": "CycloneDX", "specVersion": "1.6",
	  "metadata": {"component": {"bom-ref": "root", "type": "application", "name": "product", "version": "1"}},
	  "components": [
	    {"bom-ref": "a", "type": "container", "name": "docker-swss", "version": "master.1-aaa"},
	    {"bom-ref": "b", "type": "container", "name": "tooling", "version": "1",
	     "purl": "pkg:generic/tooling@1"},
	    {"bom-ref": "c", "type": "library", "name": "libc", "version": "2.41"}
	  ],
	  "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}, {"ref": "a", "dependsOn": ["c"]}]}`
	spdx := `{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
	  "name": "product", "documentNamespace": "https://example.invalid/product-1.0",
	  "creationInfo": {"created": "2026-08-14T09:12:33Z", "creators": ["Tool: something-1.0"]},
	  "packages": [
	    {"SPDXID": "SPDXRef-root", "name": "product", "versionInfo": "1.0", "downloadLocation": "NOASSERTION"},
	    {"SPDXID": "SPDXRef-a", "name": "docker-swss", "versionInfo": "master.1-aaa",
	     "downloadLocation": "NOASSERTION", "primaryPackagePurpose": "CONTAINER"},
	    {"SPDXID": "SPDXRef-b", "name": "tooling", "versionInfo": "1", "downloadLocation": "NOASSERTION",
	     "primaryPackagePurpose": "CONTAINER",
	     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
	                       "referenceLocator": "pkg:generic/tooling@1"}]},
	    {"SPDXID": "SPDXRef-c", "name": "libc", "versionInfo": "2.41", "downloadLocation": "NOASSERTION",
	     "primaryPackagePurpose": "LIBRARY"}
	  ],
	  "relationships": [
	    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "DESCRIBES"},
	    {"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "CONTAINS"},
	    {"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-b", "relationshipType": "CONTAINS"},
	    {"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-c", "relationshipType": "CONTAINS"}
	  ]}`
	for name, body := range map[string]string{"CycloneDX": cyclonedx, "SPDX 2": spdx} {
		t.Run(name, func(t *testing.T) {
			doc := read(t, body)
			for _, d := range doc.Components {
				if want := d.Name == "docker-swss"; d.IsImage() != want {
					t.Errorf("%s reads as an image: %v, want %v", d.Name, d.IsImage(), want)
				}
			}
		})
	}
}
