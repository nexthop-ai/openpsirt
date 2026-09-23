// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// read parses a document the way the command does, so the tests exercise the
// same unmarshalling the real inputs go through.
func read(t *testing.T, body string) document {
	t.Helper()
	var doc document
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc
}

// A binary cataloged on its own: a proper graph, with the main module above
// everything it was linked from, and no knowledge of the image around it.
const oneBinary = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"timestamp": "2026-09-04T00:00:00Z",
    "component": {"bom-ref": "file-ref", "type": "file", "name": "grype"}},
  "components": [
    {"bom-ref": "g", "type": "library", "name": "grype", "version": "0.118.0",
     "purl": "pkg:golang/github.com/anchore/grype@0.118.0?package-id=aaa"},
    {"bom-ref": "c", "type": "library", "name": "containerd", "version": "2.2.2",
     "purl": "pkg:golang/github.com/containerd/containerd@2.2.2?package-id=bbb"}
  ],
  "dependencies": [{"ref": "g", "dependsOn": ["c"]}]
}`

// A filesystem cataloged on its own: distribution packages with their own
// edges, and nothing above them.
const theFilesystem = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"timestamp": "2026-09-04T00:00:00Z",
    "component": {"bom-ref": "dir-ref", "type": "file", "name": "/rootfs"}},
  "components": [
    {"bom-ref": "b", "type": "library", "name": "busybox", "version": "1.37.0",
     "purl": "pkg:apk/alpine/busybox@1.37.0?package-id=ccc"},
    {"bom-ref": "m", "type": "library", "name": "musl", "version": "1.2.5",
     "purl": "pkg:apk/alpine/musl@1.2.5?package-id=ddd"}
  ],
  "dependencies": [{"ref": "b", "dependsOn": ["m"]}]
}`

func kids(t *testing.T, doc *document, ref string) []string {
	t.Helper()
	for _, dep := range doc.Dependencies {
		if dep.Ref == ref {
			return dep.DependsOn
		}
	}
	return nil
}

func TestEachPartsOwnGraphSurvivesAndTheImageIsAboveIt(t *testing.T) {
	// The whole point. Cataloging a directory loses the structure inside a
	// binary; cataloging a binary loses the image around it. Composing keeps
	// both, and adds only the edge that "this image contains that" already
	// means.
	composed, err := compose("openpsirt-image", "1.0",
		[]document{read(t, theFilesystem), read(t, oneBinary)})
	if err != nil {
		t.Fatal(err)
	}

	if got := composed.Metadata.Component.Name; got != "openpsirt-image" {
		t.Errorf("the composed root is %q", got)
	}
	if len(composed.Components) != 4 {
		t.Fatalf("%d components, want the four the two inputs described", len(composed.Components))
	}

	// The image contains what nothing else placed: the package no other
	// package pulls in, and the main module of the binary. Not musl, which
	// busybox pulls in, and not containerd, which is inside grype.
	top := kids(t, composed, "root")
	want := map[string]bool{
		"pkg:apk/alpine/busybox@1.37.0":               true,
		"pkg:golang/github.com/anchore/grype@0.118.0": true,
	}
	if len(top) != len(want) {
		t.Fatalf("the image contains %v directly, want the two nothing else placed", top)
	}
	for _, ref := range top {
		if !want[ref] {
			t.Errorf("%q is directly under the image and something else places it", ref)
		}
	}

	// And each part's own structure is still there.
	if got := kids(t, composed, "pkg:golang/github.com/anchore/grype@0.118.0"); len(got) != 1 ||
		got[0] != "pkg:golang/github.com/containerd/containerd@2.2.2" {
		t.Errorf("what is inside the binary reads as %v", got)
	}
	if got := kids(t, composed, "pkg:apk/alpine/busybox@1.37.0"); len(got) != 1 ||
		got[0] != "pkg:apk/alpine/musl@1.2.5" {
		t.Errorf("what the package pulls in reads as %v", got)
	}
}

func TestAModuleTwoBinariesShareAppearsOnceWithBothParents(t *testing.T) {
	// Two binaries in one image commonly link the same library, and the
	// producer gives it a different reference in each catalog. One component
	// with two parents is the truth; two components is a count that says the
	// image ships it twice and a decision that has to be made twice.
	second := `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [
	    {"bom-ref": "o", "type": "library", "name": "openpsirt", "version": "1.0",
	     "purl": "pkg:golang/github.com/nexthop-ai/openpsirt@1.0?package-id=eee"},
	    {"bom-ref": "c2", "type": "library", "name": "containerd", "version": "2.2.2",
	     "purl": "pkg:golang/github.com/containerd/containerd@2.2.2?package-id=fff"}
	  ],
	  "dependencies": [{"ref": "o", "dependsOn": ["c2"]}]
	}`
	composed, err := compose("openpsirt-image", "1.0",
		[]document{read(t, oneBinary), read(t, second)})
	if err != nil {
		t.Fatal(err)
	}

	var shared int
	for _, c := range composed.Components {
		if c.Name == "containerd" {
			shared++
		}
	}
	if shared != 1 {
		t.Errorf("the shared module appears %d times, want once however many link it", shared)
	}

	const it = "pkg:golang/github.com/containerd/containerd@2.2.2"
	var parents []string
	for _, dep := range composed.Dependencies {
		for _, child := range dep.DependsOn {
			if child == it {
				parents = append(parents, dep.Ref)
			}
		}
	}
	if len(parents) != 2 {
		t.Errorf("the shared module has parents %v, want both binaries", parents)
	}
	// And it is not also hanging off the image, because both binaries place it.
	for _, ref := range kids(t, composed, "root") {
		if ref == it {
			t.Error("a module both binaries place is also reported as directly in the image")
		}
	}
}

func TestWhatTheProducerSaidIsCarriedThrough(t *testing.T) {
	// Composing rewrites references and adds one edge. Everything else a
	// producer recorded about a component — licenses, hashes, the properties
	// that say where it was found — is somebody else's evidence, and dropping
	// it would make this a lossy step in the middle of an audit trail.
	rich := `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [
	    {"bom-ref": "x", "type": "library", "name": "musl", "version": "1.2.5",
	     "purl": "pkg:apk/alpine/musl@1.2.5",
	     "licenses": [{"license": {"id": "MIT"}}],
	     "properties": [{"name": "syft:location:0:path", "value": "/lib/ld-musl.so"}]}
	  ]
	}`
	composed, err := compose("openpsirt-image", "1.0", []document{read(t, rich)})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(composed.Components[0])
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatal(err)
	}
	for _, kept := range []string{"licenses", "properties", "purl", "name", "version", "type"} {
		if _, held := back[kept]; !held {
			t.Errorf("%q did not survive composing: %s", kept, body)
		}
	}
	if back["bom-ref"] != "pkg:apk/alpine/musl@1.2.5" {
		t.Errorf("the reference was not rewritten to the identity: %v", back["bom-ref"])
	}
}

func TestWhatASecondProducerSaidAboutOneComponentIsKeptToo(t *testing.T) {
	// The live composition is three inputs: a filesystem catalog, and one
	// catalog per binary. A component all three see — the Go runtime's own
	// module, a distribution package a binary also links — was described by
	// each of them and only the first description survived, taking the
	// licenses and hashes the others recorded with it.
	filesystem := `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [
	    {"bom-ref": "a", "type": "library", "name": "zlib", "version": "1.3",
	     "purl": "pkg:apk/alpine/zlib@1.3",
	     "licenses": [{"license": {"id": "Zlib"}}],
	     "hashes": [{"alg": "SHA-256", "content": "aaaa"}],
	     "externalReferences": [{"type": "website", "url": "https://zlib.example"}],
	     "properties": [{"name": "syft:location:0:path", "value": "/lib/libz.so"}]}
	  ]
	}`
	binary := `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [
	    {"bom-ref": "b", "type": "library", "name": "zlib", "version": "1.3",
	     "purl": "pkg:apk/alpine/zlib@1.3",
	     "licenses": [{"license": {"id": "MIT"}}],
	     "hashes": [{"alg": "SHA-512", "content": "bbbb"}],
	     "externalReferences": [{"type": "vcs", "url": "https://zlib.example/git"}],
	     "properties": [{"name": "syft:location:0:path", "value": "/usr/bin/openpsirt"}]}
	  ]
	}`
	composed, err := compose("openpsirt-image", "1.0",
		[]document{read(t, filesystem), read(t, binary)})
	if err != nil {
		t.Fatal(err)
	}
	if len(composed.Components) != 1 {
		t.Fatalf("one component described twice became %d", len(composed.Components))
	}
	body, err := json.Marshal(composed.Components[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, said := range []string{
		"Zlib", "MIT", "aaaa", "bbbb",
		// References are a producer's evidence in the same way a hash is, and
		// the shipped inventory carries them on components two catalogs both
		// describe.
		"https://zlib.example", "https://zlib.example/git",
	} {
		if !strings.Contains(string(body), said) {
			t.Errorf("%q did not survive composing: %s", said, body)
		}
	}
	// The two producers disagree about where it was found. Neither answer is
	// discarded and neither is chosen: the first stands and the second is
	// recorded beside it, which is what makes a producer disagreement
	// something a reader can see.
	for _, said := range []string{"/lib/libz.so", "/usr/bin/openpsirt", "disagreement"} {
		if !strings.Contains(string(body), said) {
			t.Errorf("%q is not in the composed properties: %s", said, body)
		}
	}
}

func TestAComponentTheNextInputPlacesIsNotAlsoHungOffTheImage(t *testing.T) {
	// Placement is asked over everything composed rather than one input at a
	// time, because the components are pooled across all of them. Asked per
	// document, a component the filesystem catalog described and the binary's
	// catalog placed fails the first document's test and hangs off the image
	// root — and the shipped inventory then says the image contains directly
	// what sits inside a binary.
	described := `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [
	    {"bom-ref": "lib", "type": "library", "name": "zlib", "version": "1.3",
	     "purl": "pkg:apk/alpine/zlib@1.3"}
	  ]
	}`
	places := `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "components": [
	    {"bom-ref": "app", "type": "application", "name": "openpsirt", "version": "1.0",
	     "purl": "pkg:golang/github.com/nexthop-ai/openpsirt@1.0"},
	    {"bom-ref": "lib", "type": "library", "name": "zlib", "version": "1.3",
	     "purl": "pkg:apk/alpine/zlib@1.3"}
	  ],
	  "dependencies": [{"ref": "app", "dependsOn": ["lib"]}]
	}`
	composed, err := compose("openpsirt-image", "1.0",
		[]document{read(t, described), read(t, places)})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range kids(t, composed, "root") {
		if ref == "pkg:apk/alpine/zlib@1.3" {
			t.Error("a component the second input places is also reported as " +
				"directly in the image")
		}
	}
	if kids := kids(t, composed, "pkg:golang/github.com/nexthop-ai/openpsirt@1.0"); len(kids) != 1 {
		t.Errorf("the application places %v, want the library it links", kids)
	}
}

func TestAComponentPlacedOnlyByItsOwnDocumentsRootIsInTheImage(t *testing.T) {
	// An input's root describes the part rather than the whole, and the whole
	// is the image here — so its children are exactly what the image contains
	// directly, and the composed root is where they hang from.
	//
	// Reading those edges as placement leaves such a component nowhere: not a
	// child of the composed root, because something placed it, and in no
	// dependency entry either, because the edge that placed it comes from a
	// root this does not carry over.
	const binary = `{
	  "bomFormat": "CycloneDX", "specVersion": "1.6",
	  "metadata": {"component": {"bom-ref": "self", "type": "application", "name": "openpsirt"}},
	  "components": [
	    {"bom-ref": "mod", "type": "library", "name": "golang.org/x/net", "version": "0.4.0",
	     "purl": "pkg:golang/golang.org/x/net@0.4.0"}
	  ],
	  "dependencies": [{"ref": "self", "dependsOn": ["mod"]}]
	}`
	composed, err := compose("openpsirt-image", "1.0", []document{read(t, binary)})
	if err != nil {
		t.Fatal(err)
	}
	const it = "pkg:golang/golang.org/x/net@0.4.0"
	if kids := kids(t, composed, "root"); !slices.Contains(kids, it) {
		t.Errorf("the image's children are %v, and the one component it holds is not among them", kids)
	}
}
