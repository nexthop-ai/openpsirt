// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// minimalSPDX3 describes the same product as `minimal` and `minimalSPDX`: one
// product with one library under it. The third version states that as a flat
// graph of typed elements rather than as a document with contents.
const minimalSPDX3 = `{
  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
  "@graph": [
    {"@id": "_:creationInfo", "type": "CreationInfo", "specVersion": "3.0.1",
     "created": "2026-08-14T09:12:33Z"},
    {"spdxId": "https://example.invalid/product-1.0", "type": "SpdxDocument",
     "creationInfo": "_:creationInfo", "rootElement": ["urn:root"]},
    {"spdxId": "urn:root", "type": "software_Package", "creationInfo": "_:creationInfo",
     "name": "product", "software_packageVersion": "1.0"},
    {"spdxId": "urn:a", "type": "software_Package", "creationInfo": "_:creationInfo",
     "name": "libc", "software_packageVersion": "2.41",
     "software_packageUrl": "pkg:deb/debian/libc6@2.41"},
    {"spdxId": "urn:rel", "type": "Relationship", "creationInfo": "_:creationInfo",
     "from": "urn:root", "relationshipType": "dependsOn", "to": ["urn:a"]}
  ]
}`

func TestReadsTheThirdVersionAsAGraphOfTypedElements(t *testing.T) {
	doc := read(t, minimalSPDX3)

	if doc.Root.Name != "product" || doc.Root.Version != "1.0" {
		t.Errorf("root is %q@%q", doc.Root.Name, doc.Root.Version)
	}
	if !doc.RootDeclared {
		t.Error("the document named what it is about and that was not recorded")
	}
	if want := "https://example.invalid/product-1.0"; doc.Serial != want {
		t.Errorf("serial is %q, want %q", doc.Serial, want)
	}
	if want := time.Date(2026, 8, 14, 9, 12, 33, 0, time.UTC); !doc.BuiltAt.Equal(want) {
		t.Errorf("built at %v, want %v", doc.BuiltAt, want)
	}
	if len(doc.Components) != 1 {
		t.Fatalf("read %d components, want 1", len(doc.Components))
	}
	if got := doc.Components[0].Purl; got != "pkg:deb/debian/libc6@2.41" {
		t.Errorf("package identifier is %q", got)
	}
	if got := edges(doc); !slices.Equal(got, []string{"product -> libc"}) {
		t.Errorf("edges are %v", got)
	}
}

func TestAllThreeVocabulariesReadTheSameInventoryTheSame(t *testing.T) {
	// Three documents describing one product with one library under it. What
	// comes out of the reader has to be the same thing from all three, or a
	// decision made against a build read one way lapses when the build is read
	// another.
	for _, tc := range []struct{ name, body string }{
		{"the first format", minimal},
		{"the second format", minimalSPDX},
		{"the third format", minimalSPDX3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, got := read(t, minimal), read(t, tc.body)
			if want.Root.Identity() != got.Root.Identity() {
				t.Errorf("root is %q@%q, want %q@%q",
					got.Root.Name, got.Root.Version, want.Root.Name, want.Root.Version)
			}
			if len(got.Components) != 1 {
				t.Fatalf("read %d components, want 1", len(got.Components))
			}
			if want.Components[0].Identity() != got.Components[0].Identity() {
				t.Errorf("the library reads as %q, want %q", got.Components[0].Purl, want.Components[0].Purl)
			}
			if !slices.Equal(edges(got), edges(want)) {
				t.Errorf("edges are %v, want %v", edges(got), edges(want))
			}
		})
	}
}

func TestTheExpandedSpellingsAreRead(t *testing.T) {
	// The linked form of the two keys that identify an element. No fixture
	// uses either — every one of them writes `spdxId` and `type` — so the
	// expanded spelling is a branch the whole suite leaves green when it is
	// deleted, and the paths check cannot catch it either.
	for _, tc := range []struct{ name, from, to string }{
		{"the type", `"type":`, `"@type":`},
		{"the identifier", `"spdxId":`, `"@id":`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := read(t, strings.ReplaceAll(minimalSPDX3, tc.from, tc.to))
			if len(doc.Components) != 1 {
				t.Fatalf("read %d components, want 1", len(doc.Components))
			}
			if got := edges(doc); !slices.Equal(got, []string{"product -> libc"}) {
				t.Errorf("edges are %v", got)
			}
		})
	}
}

func TestTheTypeMayArriveAfterTheFieldsItGoverns(t *testing.T) {
	// The order of an object's keys is the producer's business, so an element
	// is read into one neutral shape and interpreted when it closes. A reader
	// that branched on the type as it arrived would read the same document two
	// ways depending on how its producer serialized it.
	last := strings.NewReplacer(
		`"spdxId": "urn:a", "type": "software_Package", "creationInfo": "_:creationInfo",
     "name": "libc", "software_packageVersion": "2.41",
     "software_packageUrl": "pkg:deb/debian/libc6@2.41"`,
		`"name": "libc", "software_packageVersion": "2.41",
     "software_packageUrl": "pkg:deb/debian/libc6@2.41",
     "spdxId": "urn:a", "creationInfo": "_:creationInfo", "type": "software_Package"`,
	).Replace(minimalSPDX3)

	doc := read(t, last)
	if len(doc.Components) != 1 || doc.Components[0].Purl != "pkg:deb/debian/libc6@2.41" {
		t.Fatalf("read %d components with a type stated last", len(doc.Components))
	}
	if got := edges(doc); !slices.Equal(got, []string{"product -> libc"}) {
		t.Errorf("edges are %v", got)
	}
}

func TestAThirdVersionWrittenWithTheSecondFormatsPrefixIsRead(t *testing.T) {
	// go-FuSa 0.25 writes the version this way.
	doc := read(t, `{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [
		{"type": "CreationInfo", "spdxId": "_:c", "specVersion": "SPDX-3.0.1",
		 "created": "2026-06-11T17:19:31Z"},
		{"type": "software_Package", "spdxId": "https://example.org/p", "name": "otel",
		 "creationInfo": "_:c", "software_packageVersion": "v1.44.0"}]}`)
	if len(doc.Components) != 1 {
		t.Errorf("read %d components, want the one package", len(doc.Components))
	}
}

func TestTheThirdVersionIsRefusedWhereItWasNotWrittenAgainst(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{{
		name: "a fourth major version in the context",
		body: `{"@context": "https://spdx.org/rdf/4.0.0/spdx-context.jsonld", "@graph": []}`,
		want: `version "https://spdx.org/rdf/4.0.0/spdx-context.jsonld" is not one this reads`,
	}, {
		name: "a fourth major version in the graph",
		body: `{"@graph": [{"@id": "_:c", "type": "CreationInfo", "specVersion": "4.0.0"}]}`,
		want: `version "4.0.0" is not one this reads`,
	}, {
		name: "a fourth major version written with the prefix",
		body: `{"@graph": [{"@id": "_:c", "type": "CreationInfo", "specVersion": "SPDX-4.0.0"}]}`,
		want: `version "SPDX-4.0.0" is not one this reads`,
	}, {
		name: "a linked document of some other kind",
		body: `{"@context": "https://example.invalid/other.jsonld", "@graph": [{"type": "Thing"}]}`,
		want: "does not say what format it is",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if why := refuses(t, tc.body); !strings.Contains(why, tc.want) {
				t.Errorf("refused with %q, want it to mention %q", why, tc.want)
			}
		})
	}
}

func TestTheThirdVersionDeclaresItselfFromEitherPlace(t *testing.T) {
	// The version is in the context and in every creation-information element,
	// and a producer need not emit the first. Read from one place only, a
	// document stating it in the other is refused as saying nothing.
	t.Run("from the context alone", func(t *testing.T) {
		body := strings.Replace(minimalSPDX3, `"specVersion": "3.0.1",`, "", 1)
		if doc := read(t, body); len(doc.Components) != 1 {
			t.Errorf("read %d components, want 1", len(doc.Components))
		}
	})
	t.Run("from the graph alone", func(t *testing.T) {
		body := strings.Replace(minimalSPDX3,
			`"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",`,
			`"@context": "https://example.invalid/other.jsonld",`, 1)
		if doc := read(t, body); len(doc.Components) != 1 {
			t.Errorf("read %d components, want 1", len(doc.Components))
		}
	})
}

func TestTheBuildTimeComesFromTheDocumentsOwnCreationRecord(t *testing.T) {
	// A document carries more than one, because anything it imported brought
	// its own. Taking whichever was read first would order scans against each
	// other by a time that belongs to somebody else's document.
	body := strings.Replace(minimalSPDX3, `"@graph": [`, `"@graph": [`+
		`{"@id": "_:imported", "type": "CreationInfo", "specVersion": "3.0.1",`+
		` "created": "2019-01-01T00:00:00Z"},`, 1)

	doc := read(t, body)
	if want := time.Date(2026, 8, 14, 9, 12, 33, 0, time.UTC); !doc.BuiltAt.Equal(want) {
		t.Errorf("built at %v, want %v — the imported document's time is not ours", doc.BuiltAt, want)
	}
}

func TestTheHeaderOfTheThirdVersionIsReadFromInsideTheContents(t *testing.T) {
	// This format puts the header in the same array as the packages, so the
	// header read walks the whole graph. What it must not do is build anything
	// from it — which `!RootDeclared` does not show, since resolveRoot returns
	// on any header read whatever the graph left behind.
	//
	// It is shown by a document the full read refuses. A nameless package is
	// a fault in the contents, and the other two formats skip their contents
	// on this pass, so the same document is answered 202 and fails later in
	// the background reader. Reporting it here instead would have the same
	// fault surface at two different times depending on which format a build
	// happens to emit.
	nameless := strings.Replace(minimalSPDX3, `"name": "libc", `, "", 1)

	if _, err := sbom.Read(strings.NewReader(nameless), sbom.Limits{}); err == nil {
		t.Fatal("a whole read accepted a package with no name")
	}

	header, err := sbom.ReadHeader(strings.NewReader(nameless), sbom.Limits{})
	if err != nil {
		t.Fatalf("a header read was refused for something in the contents: %v", err)
	}
	if want := "https://example.invalid/product-1.0"; header.Serial != want {
		t.Errorf("serial is %q, want %q", header.Serial, want)
	}
	if want := time.Date(2026, 8, 14, 9, 12, 33, 0, time.UTC); !header.BuiltAt.Equal(want) {
		t.Errorf("built at %v, want %v", header.BuiltAt, want)
	}

	// The bounds still hold on that pass, because what they stop is the walk.
	var b strings.Builder
	b.WriteString(`{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [`)
	for i := range 50 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"spdxId": "urn:f%d", "type": "software_File", "name": "f%d"}`, i, i)
	}
	b.WriteString(`]}`)
	if _, err := sbom.ReadHeader(strings.NewReader(b.String()), sbom.Limits{MaxFiles: 10}); err == nil {
		t.Error("a header read walked past a bound rather than charging it")
	}
}

func TestTheThirdVersionStatesStructureInOneDirection(t *testing.T) {
	// The reversed spellings the second version carried are gone: every
	// relationship reads from its subject to its object. So a type is an edge
	// or it is not, and there is no direction to get wrong.
	for _, kind := range []string{
		"contains", "dependsOn", "hasDynamicLink", "hasStaticLink",
		"hasPrerequisite", "hasOptionalComponent", "hasOptionalDependency",
		"hasProvidedDependency",
	} {
		t.Run(kind, func(t *testing.T) {
			doc := read(t, strings.Replace(minimalSPDX3, `"relationshipType": "dependsOn"`,
				`"relationshipType": "`+kind+`"`, 1))
			if got := edges(doc); !slices.Equal(got, []string{"product -> libc"}) {
				t.Errorf("edges are %v", got)
			}
		})
	}
}

func TestWhatTheThirdVersionSaysAboutABuildIsNotStructure(t *testing.T) {
	for _, kind := range []string{
		"usesTool", "hasTestCase", "hasTest", "generates", "hasInput", "hasOutput",
		"hasHost", "hasDocumentation", "hasExample", "hasEvidence", "hasMetadata",
		"amendedBy", "patchedBy", "hasDistributionArtifact", "availableFrom",
		"hasConcludedLicense", "hasDeclaredLicense", "other",
	} {
		t.Run(kind, func(t *testing.T) {
			doc := read(t, strings.Replace(minimalSPDX3, `"relationshipType": "dependsOn"`,
				`"relationshipType": "`+kind+`"`, 1))
			if len(doc.Dependencies) != 0 {
				t.Errorf("%s became %d edge(s)", kind, len(doc.Dependencies))
			}
			if len(doc.Components) != 1 {
				t.Errorf("read %d components, want 1 — the component still ships", len(doc.Components))
			}
		})
	}
}

func TestALifecycleScopeSaysWhenNotWhether(t *testing.T) {
	// The one judgment in this vocabulary that the specification does not
	// make for us. A scope says which phase a relationship matters in, and
	// says nothing about whether the target ships. Reading `build` as "does not
	// ship" is wrong for every compiled language — a crate linked into a binary
	// is stated as a build-phase dependency and is inside what ships — and
	// getting it wrong in that direction hides findings rather than adding
	// noise. A test dependency is the exception, and it is the same exception
	// the second version's table makes.
	//
	// The exception drops the edge and not the component: the package
	// is in the document either way, so it is held and counted as sitting
	// under nothing.
	scoped := func(scope string) string {
		return strings.Replace(minimalSPDX3, `"type": "Relationship", "creationInfo": "_:creationInfo",`,
			`"type": "LifecycleScopedRelationship", "creationInfo": "_:creationInfo", "scope": "`+scope+`",`, 1)
	}

	for _, scope := range []string{"build", "runtime", "design", "development", "other"} {
		t.Run(scope+" ships", func(t *testing.T) {
			doc := read(t, scoped(scope))
			if got := edges(doc); !slices.Equal(got, []string{"product -> libc"}) {
				t.Errorf("edges are %v", got)
			}
		})
	}

	t.Run("test does not", func(t *testing.T) {
		doc := read(t, scoped("test"))
		if len(doc.Dependencies) != 0 {
			t.Errorf("a test dependency became %d edge(s)", len(doc.Dependencies))
		}
		if doc.Unrooted != 1 {
			t.Errorf("%d components sit under nothing, want 1 — it is in the document either way", doc.Unrooted)
		}
	})
}

func TestAnIdentifierStatedBesideTheElementIsRead(t *testing.T) {
	// The format states a package identifier as a field of the package and as
	// an external identifier, and the national database key only the second
	// way. No example emits either as an external identifier, so this is
	// constructed rather than taken from a fixture — which is where a rule
	// belongs when the documents to hand do not exercise it.
	body := strings.Replace(minimalSPDX3,
		`"software_packageUrl": "pkg:deb/debian/libc6@2.41"`,
		`"externalIdentifier": [
       {"type": "ExternalIdentifier", "externalIdentifierType": "packageUrl",
        "identifier": "pkg:deb/debian/libc6@2.41"},
       {"type": "ExternalIdentifier", "externalIdentifierType": "cpe23",
        "identifier": "cpe:2.3:a:gnu:glibc:2.41:*:*:*:*:*:*:*"},
       {"type": "ExternalIdentifier", "externalIdentifierType": "email",
        "identifier": "nobody@example.invalid"}]`, 1)

	doc := read(t, body)
	if len(doc.Components) != 1 {
		t.Fatalf("read %d components, want 1", len(doc.Components))
	}
	if got := doc.Components[0].Purl; got != "pkg:deb/debian/libc6@2.41" {
		t.Errorf("package identifier is %q", got)
	}
	if got := doc.Components[0].CPE; got != "cpe:2.3:a:gnu:glibc:2.41:*:*:*:*:*:*:*" {
		t.Errorf("database key is %q", got)
	}
}

func TestTheThirdVersionChargesTheSameBounds(t *testing.T) {
	// Every entry of the graph is charged against the component bound, because
	// which entries turn out to be components is not known until each has been
	// read — and an unbounded array is an unbounded walk whatever it holds.
	for _, tc := range []struct {
		name  string
		limit sbom.Limits
		want  string
	}{
		{"elements", sbom.Limits{MaxComponents: 3}, "component limit"},
		{"edges", sbom.Limits{MaxEdges: 0, MaxComponents: 100, MaxDepth: 3}, "level limit"},
		{"size", sbom.Limits{MaxBytes: 64}, "larger than the configured limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sbom.Read(strings.NewReader(minimalSPDX3), tc.limit)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused with %q, want it to mention %q", err, tc.want)
			}
		})
	}

	t.Run("one relationship reaching many elements", func(t *testing.T) {
		// The edge bound is charged per element reached rather than per
		// relationship, because one relationship states a list.
		var b strings.Builder
		b.WriteString(`{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [` +
			`{"spdxId": "urn:r", "type": "Relationship", "from": "urn:x", "relationshipType": "contains", "to": [`)
		for i := range 20 {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`"urn:to"`)
		}
		b.WriteString(`]}]}`)

		_, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxEdges: 5})
		if err == nil {
			t.Fatal("twenty ends passed a bound of five")
		} else if !strings.Contains(err.Error(), "dependency limit") {
			t.Errorf("refused with %q", err)
		}
	})
}

func TestReadsTheThirdVersionsOwnExamples(t *testing.T) {
	t.Run("the same application as the second version's fixture", func(t *testing.T) {
		// Example 11 in both versions, which is what makes the pair worth
		// keeping: the same Rust application, described twice.
		second, err := sbom.Read(fixture(t, "rust-app.spdx.json"), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		third, err := sbom.Read(fixture(t, "rust-app.spdx3.json"), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if second.Root.Name != third.Root.Name {
			t.Errorf("roots are %q and %q", second.Root.Name, third.Root.Name)
		}
		if len(second.Components) != len(third.Components) {
			t.Errorf("read %d and %d components", len(second.Components), len(third.Components))
		}
		if len(second.Dependencies) != len(third.Dependencies) {
			t.Errorf("read %d and %d edges", len(second.Dependencies), len(third.Dependencies))
		}
	})

	t.Run("the same application described the other way round", func(t *testing.T) {
		// Example 14 in both versions, and they disagree. The second states
		// the application dynamically linking each library; the third states
		// each library dynamically linking the application, which is the
		// opposite of what the relationship means. Nothing here corrects it:
		// the edges are read as stated, so every library sits under nothing
		// where the second version has four of them under the application.
		//
		// That is what the unplaced count is for. It is a number that should
		// be stable build to build, so a change in it says the producer
		// changed — and here it says the conversion did.
		second, err := sbom.Read(fixture(t, "maven-app.spdx.json"), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		third, err := sbom.Read(fixture(t, "maven-app.spdx3.json"), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if second.Unrooted != 1 {
			t.Errorf("%d components sit under nothing in the second version, want 1", second.Unrooted)
		}
		if third.Unrooted != 5 {
			t.Errorf("%d components sit under nothing in the third version, want 5", third.Unrooted)
		}
		if len(second.Dependencies) != len(third.Dependencies) {
			t.Errorf("read %d and %d edges — the same edges, pointing the other way",
				len(second.Dependencies), len(third.Dependencies))
		}
	})

	t.Run("an inventory element that names the root", func(t *testing.T) {
		// The root is stated on an inventory element rather than on the
		// document, which is a shape only this version has.
		doc, err := sbom.Read(fixture(t, "acme-app.spdx3.json"), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if doc.Root.Name != "Acme Application" || doc.Root.Version != "1.3" {
			t.Errorf("root is %q@%q", doc.Root.Name, doc.Root.Version)
		}
		if len(doc.Components) != 3 || len(doc.Dependencies) != 3 {
			t.Errorf("read %d components and %d edges, want 3 and 3",
				len(doc.Components), len(doc.Dependencies))
		}
	})

	t.Run("the largest of them", func(t *testing.T) {
		// A hundred and three elements: seven packages, fifteen files and
		// sixty-three relationships, most of which say nothing about
		// structure. Six packages survive as components because one of the
		// seven is the root, and eighteen of its edges name a file.
		doc, err := sbom.Read(fixture(t, "appbom.spdx3.json"), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		if doc.Root.Name != "App-BOM-ination" {
			t.Errorf("root is %q", doc.Root.Name)
		}
		if len(doc.Components) != 6 {
			t.Errorf("read %d components, want 6", len(doc.Components))
		}
		if len(doc.Dependencies) != 3 {
			t.Errorf("read %d edges, want 3", len(doc.Dependencies))
		}
		if doc.FileReferences != 18 {
			t.Errorf("%d edges named a file, want 18", doc.FileReferences)
		}
		if doc.DanglingEdges != 0 {
			t.Errorf("%d edges named nothing, want 0", doc.DanglingEdges)
		}
	})
}

func TestTheThirdVersionBoundsPathsApartFromComponentsToo(t *testing.T) {
	// This format does not say what an element is until the element has been
	// read, so every entry is charged as a component on the way in and the
	// ones that turn out to be paths are moved. Without the move, a real image
	// scan — forty-five to fifty-six paths per package — spends a component
	// ceiling that was sized for components.
	body := func(files int) string {
		var b strings.Builder
		b.WriteString(`{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [`)
		for i := range files {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"spdxId": "urn:f%d", "type": "software_File", "name": "usr/lib/f%d"}`, i, i)
		}
		b.WriteString(`]}`)
		return b.String()
	}

	if _, err := sbom.Read(strings.NewReader(body(50)), sbom.Limits{MaxFiles: 10}); err == nil {
		t.Fatal("fifty paths passed a bound of ten")
	} else if !strings.Contains(err.Error(), "file limit") {
		t.Errorf("refused with %q", err)
	}

	// And they hand the component charge back, so a document of paths is not a
	// document of components.
	if _, err := sbom.Read(strings.NewReader(body(50)), sbom.Limits{MaxComponents: 10}); err != nil {
		t.Errorf("fifty paths spent a component bound of ten: %v", err)
	}
}

func TestTheThirdVersionRefusesAPathAndAPackageSharingAnIdentifier(t *testing.T) {
	// Both orderings, because this format states paths and packages in one
	// array and which comes first is the producer's business. One of the two
	// is caught where a package is bound and the other where a path is
	// recorded, and a test covering one ordering only leaves half of that
	// unexercised — which is how the first draft of this test passed with the
	// second check deleted.
	const path = `{"spdxId": "urn:a", "type": "software_File", "name": "usr/lib/libc.so.6"}`

	t.Run("the path first", func(t *testing.T) {
		body := strings.Replace(minimalSPDX3, `"@graph": [`, `"@graph": [`+path+`,`, 1)
		if why := refuses(t, body); !strings.Contains(why, "file and a component share the identifier") {
			t.Errorf("refused with %q", why)
		}
	})

	t.Run("the package first", func(t *testing.T) {
		body := strings.Replace(minimalSPDX3, `{"spdxId": "urn:rel"`, path+`,{"spdxId": "urn:rel"`, 1)
		if why := refuses(t, body); !strings.Contains(why, "file and a component share the identifier") {
			t.Errorf("refused with %q", why)
		}
	})
}

func TestADocumentStatingTwoVersionsOfOneFormatIsRefused(t *testing.T) {
	// Two major versions of one format are as unreadable together as two
	// formats are, and for the same reason: a handler writes the document's
	// identity before anything has checked what the document is, so a file
	// carrying keys from both is stored under whichever handler ran last.
	//
	// Recorded per vocabulary rather than per format, because keyed by format
	// these two are one entry and the refusal can never fire between them.
	both := `{
	  "spdxVersion": "SPDX-2.3", "documentNamespace": "https://example.invalid/two",
	  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
	  "packages": [{"SPDXID": "SPDXRef-a", "name": "libc", "versionInfo": "2.41"}],
	  "@graph": [{"spdxId": "urn:a", "type": "software_Package", "name": "libc"}]
	}`
	if why := refuses(t, both); !strings.Contains(why, "states both SPDX 2.x and SPDX 3.x") {
		t.Errorf("refused with %q", why)
	}

	// And with the two identity keys the other way round, which is the
	// property that matters — the same bytes must not read two ways.
	swapped := `{
	  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
	  "@graph": [{"spdxId": "urn:a", "type": "software_Package", "name": "libc"}],
	  "spdxVersion": "SPDX-2.3", "documentNamespace": "https://example.invalid/two",
	  "packages": [{"SPDXID": "SPDXRef-a", "name": "libc", "versionInfo": "2.41"}]
	}`
	if why := refuses(t, swapped); !strings.Contains(why, "states both SPDX 2.x and SPDX 3.x") {
		t.Errorf("refused with %q", why)
	}
}

func TestADerivationTheThirdVersionStatesIsNotThrownAway(t *testing.T) {
	// Read, charged against the claim bound, and then dropped, because the
	// slice the resolution walks was only ever appended to on the other
	// version's path. The package came out with no upstream at all where the
	// byte-equivalent 2.x document fills both fields — and the version is what
	// expiry compares.
	body := strings.Replace(minimalSPDX3, `"@graph": [`, `"@graph": [`+
		`{"spdxId": "urn:up", "type": "software_Package", "name": "glibc",`+
		` "software_packageVersion": "2.41-9"},`+
		`{"spdxId": "urn:anc", "type": "Relationship", "from": "urn:up",`+
		` "relationshipType": "ancestorOf", "to": ["urn:a"]},`, 1)

	doc := read(t, body)
	var found bool
	for _, c := range doc.Components {
		if c.Name != "libc" {
			continue
		}
		found = true
		if c.UpstreamName != "glibc" || c.UpstreamVersion != "2.41-9" {
			t.Errorf("derived from %q@%q, want glibc@2.41-9", c.UpstreamName, c.UpstreamVersion)
		}
	}
	if !found {
		t.Error("the component the relationship was about is not in the document")
	}
}

func TestWhatTheThirdVersionSaysItIsAboutIsBounded(t *testing.T) {
	// One graph entry is charged one component on the way in, and without a
	// per-element charge that entry carries an array as long as the byte bound
	// allows — in the synchronous upload request.
	var b strings.Builder
	b.WriteString(`{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [` +
		`{"spdxId": "urn:d", "type": "SpdxDocument", "rootElement": [`)
	for i := range 50 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"urn:a"`)
	}
	b.WriteString(`]}]}`)

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 10}); err == nil {
		t.Fatal("fifty references passed a bound of ten")
	} else if !strings.Contains(err.Error(), "component limit") {
		t.Errorf("refused with %q", err)
	}
}

func TestARelationshipDoesNotSpendTheComponentBound(t *testing.T) {
	// This format states file membership as a relationship, so a real image
	// scan carries far more relationships than packages. Charged as components
	// they refuse a document well inside both real ceilings, naming a bound it
	// never exceeded.
	var b strings.Builder
	b.WriteString(`{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [` +
		`{"spdxId": "urn:a", "type": "software_Package", "name": "libc"}`)
	for i := range 50 {
		fmt.Fprintf(&b, `,{"spdxId": "urn:r%d", "type": "Relationship", "from": "urn:a",`+
			` "relationshipType": "contains", "to": ["urn:a"]}`, i)
	}
	b.WriteString(`]}`)

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 10}); err != nil {
		t.Errorf("fifty relationships spent a component bound of ten: %v", err)
	}
	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxEdges: 10}); err == nil {
		t.Error("fifty relationship ends passed an edge bound of ten")
	}
}

func TestADocumentThatDoesNotPointAtItsOwnCreationRecordSaysNoBuildTime(t *testing.T) {
	// Standing in another record's time records a value that does not move
	// between builds, so the first scan is taken and every later one is
	// refused as not newer — for good. The upload refuses a missing build time
	// at the door instead, which is a message about this upload rather than a
	// target that quietly stops accepting them.
	//
	// Reachable: only the document element records the pointer, so a graph
	// carrying an inventory element and no document element falls through.
	body := strings.Replace(minimalSPDX3,
		`{"spdxId": "https://example.invalid/product-1.0", "type": "SpdxDocument",
     "creationInfo": "_:creationInfo", "rootElement": ["urn:root"]}`,
		`{"spdxId": "urn:sbom", "type": "software_Sbom", "rootElement": ["urn:root"]}`, 1)

	doc := read(t, body)
	if !doc.BuiltAt.IsZero() {
		t.Errorf("built at %v, want nothing — no record of this document's own was pointed at", doc.BuiltAt)
	}
	// The rest of the document still reads, so what is missing is one fact
	// rather than the file.
	if len(doc.Components) != 1 {
		t.Errorf("read %d components, want 1", len(doc.Components))
	}
}

func TestABuildTimeThatIsNotATimeSaysSo(t *testing.T) {
	// Swallowed, the upload answers "does not say when it was built" when it
	// did say, and said it wrongly — which sends whoever is debugging it
	// looking for a missing field rather than a malformed one. Both other
	// formats refuse this with the accurate text.
	body := strings.Replace(minimalSPDX3, `"created": "2026-08-14T09:12:33Z"`,
		`"created": "last Tuesday"`, 1)
	if why := refuses(t, body); !strings.Contains(why, `build time "last Tuesday" is not a time`) {
		t.Errorf("refused with %q", why)
	}
}

func TestOnlyTheDocumentSaysWhatABuildIsAbout(t *testing.T) {
	// The second version names a constant for the document's own identifier
	// precisely so a describes relationship from anything else is not taken
	// as a root claim. Without the same test here any element could make
	// itself the build's root and re-parent the whole inventory under it.
	//
	// The order is the other half: which element is the document is itself
	// stated by an element, in no fixed position, so the relationship can be
	// read before the answer exists.
	describing := func(from string, elements ...string) string {
		return `{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		  "@graph": [
		    {"spdxId": "urn:rel", "type": "Relationship", "creationInfo": "_:c",
		     "from": "` + from + `", "relationshipType": "describes", "to": ["urn:a"]},
		    {"@id": "_:c", "type": "CreationInfo", "specVersion": "3.0.1",
		     "created": "2026-08-14T09:12:33Z"},` + strings.Join(elements, ",") + `,
		    {"spdxId": "urn:a", "type": "software_Package", "creationInfo": "_:c",
		     "name": "libc", "software_packageVersion": "2.41",
		     "software_packageUrl": "pkg:deb/debian/libc6@2.41"},
		    {"spdxId": "urn:other", "type": "software_Package", "creationInfo": "_:c",
		     "name": "unrelated", "software_packageVersion": "1.0"}]}`
	}
	const document = `{"spdxId": "urn:doc", "type": "SpdxDocument", "creationInfo": "_:c"}`

	// From the document, read before the element that says which identifier
	// the document is.
	doc := read(t, describing("urn:doc", document))
	if doc.Root.Name != "libc" || !doc.RootDeclared {
		t.Errorf("the document said what it is about and the root is %q (declared: %v)",
			doc.Root.Name, doc.RootDeclared)
	}

	// From another element, which says nothing about what this build is.
	doc = read(t, describing("urn:other", document))
	if doc.RootDeclared {
		t.Errorf("an element that is not the document made %q the build's root", doc.Root.Name)
	}
}

func TestARelationshipsScopeIsRecordedOnTheEdge(t *testing.T) {
	// This version states the phase as a scope on an ordinary dependency. The
	// reader already refused to read it as "does not ship", correctly, and
	// then threw it away — which is a different thing and is what left the
	// tool unable to express the deferral class at all.
	for _, tc := range []struct {
		stated string
		want   string
	}{
		{"build", "build"},
		{"development", "development"},
		{"runtime", "runtime"},
		{"design", "design"},
		{"other", "other"},
		{"nonsense", ""},
	} {
		t.Run(tc.stated, func(t *testing.T) {
			doc := read(t, strings.Replace(minimalSPDX3,
				`"relationshipType": "dependsOn"`,
				`"relationshipType": "dependsOn", "scope": "`+tc.stated+`"`, 1))
			if len(doc.Dependencies) != 1 {
				t.Fatalf("read %d edges, want 1", len(doc.Dependencies))
			}
			if got := doc.Dependencies[0].Kind; got != tc.want {
				t.Errorf("the edge says %q, want %q", got, tc.want)
			}
		})
	}

	// The one exception, unchanged: a test dependency places nothing, and
	// there is no edge for a word to sit on.
	doc := read(t, strings.Replace(minimalSPDX3,
		`"relationshipType": "dependsOn"`,
		`"relationshipType": "dependsOn", "scope": "test"`, 1))
	if len(doc.Dependencies) != 0 {
		t.Errorf("a test-scoped dependency became %d edge(s)", len(doc.Dependencies))
	}
	if len(doc.Components) != 1 {
		t.Errorf("read %d components, want 1 — the component is still held", len(doc.Components))
	}
}
