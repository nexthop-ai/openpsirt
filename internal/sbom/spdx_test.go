package sbom_test

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// minimalSPDX is the smallest document of this format that says enough to be
// read. Written to mirror `minimal`, so the two formats can be compared at
// their floor as well as at their fixtures.
const minimalSPDX = `{
  "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
  "name": "product", "documentNamespace": "https://example.invalid/product-1.0",
  "creationInfo": {"created": "2026-08-14T09:12:33Z", "creators": ["Tool: something-1.0"]},
  "packages": [
    {"SPDXID": "SPDXRef-root", "name": "product", "versionInfo": "1.0", "downloadLocation": "NOASSERTION"},
    {"SPDXID": "SPDXRef-a", "name": "libc", "versionInfo": "2.41", "downloadLocation": "NOASSERTION",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:deb/debian/libc6@2.41"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "DESCRIBES"},
    {"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "DEPENDS_ON"}
  ]
}`

func TestReadsTheSecondFormatWithoutBeingToldWhichItIs(t *testing.T) {
	// Nothing chooses a reader. A document says what it is, and the key a
	// producer used is what routes it — which is what lets one upload path
	// take either format.
	doc := read(t, minimalSPDX)

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
		t.Fatalf("read %d components, want 1 — the root is not repeated among them", len(doc.Components))
	}
	if got := doc.Components[0].Purl; got != "pkg:deb/debian/libc6@2.41" {
		t.Errorf("package identifier is %q", got)
	}
	if got := edges(doc); !slices.Equal(got, []string{"product -> libc"}) {
		t.Errorf("edges are %v", got)
	}
}

func TestTheHeaderOfTheSecondFormatIsReadWithoutItsContents(t *testing.T) {
	// The arrival decision turns on identity and build time and on nothing
	// else, so the packages are walked past rather than built.
	header, err := sbom.ReadHeader(strings.NewReader(minimalSPDX), sbom.Limits{})
	if err != nil {
		t.Fatalf("read header: %v", err)
	}
	if want := "https://example.invalid/product-1.0"; header.Serial != want {
		t.Errorf("serial is %q, want %q", header.Serial, want)
	}
	if want := time.Date(2026, 8, 14, 9, 12, 33, 0, time.UTC); !header.BuiltAt.Equal(want) {
		t.Errorf("built at %v, want %v", header.BuiltAt, want)
	}
	// The root is stated by pointing at a package, and the packages were not
	// read — so this format answers the question the other one answers, and
	// nothing asks it of a header.
	if header.RootDeclared {
		t.Error("a header-only read resolved a root it never read the packages for")
	}
}

func TestBothFormatsAreRefusedByNameRatherThanAtAField(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{{
		name: "a third major version of the second format",
		body: `{"spdxVersion": "SPDX-3.0.1", "packages": []}`,
		want: `version "SPDX-3.0.1" is not one this reads`,
	}, {
		name: "a second major version of the first format",
		body: `{"bomFormat": "CycloneDX", "specVersion": "2.0"}`,
		want: `version "2.0" is not one this reads`,
	}, {
		name: "one format claiming to be the other",
		body: `{"bomFormat": "SPDX", "specVersion": "2.3"}`,
		want: `scan file is not CycloneDX: it says "SPDX"`,
	}, {
		name: "a version string of no format at all",
		body: `{"spdxVersion": "2.3", "packages": []}`,
		want: `scan file is not SPDX: it says "2.3"`,
	}, {
		name: "a document that never said what it was",
		body: `{"packages": [{"SPDXID": "SPDXRef-a", "name": "libc"}]}`,
		want: "does not say what format it is",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if why := refuses(t, tc.body); !strings.Contains(why, tc.want) {
				t.Errorf("refused with %q, want it to mention %q", why, tc.want)
			}
		})
	}
}

func TestTheMinorRevisionsOfTheSecondFormatAreBothRead(t *testing.T) {
	// One vocabulary covers both: the later revision adds fields and adds
	// nothing this reads. Pinned so that refusing one of them is a decision
	// rather than a regression.
	for _, version := range []string{"SPDX-2.2", "SPDX-2.3"} {
		doc := read(t, strings.Replace(minimalSPDX, `"SPDX-2.3"`, `"`+version+`"`, 1))
		if len(doc.Components) != 1 {
			t.Errorf("%s: read %d components, want 1", version, len(doc.Components))
		}
	}
}

func TestTheFormatsClaimNoKeyInCommon(t *testing.T) {
	// A top-level key is read by the format that owns it, before the document
	// has necessarily said which format it is — a producer sorting its keys
	// puts one format's packages ahead of its own version statement. That is
	// only safe while no key means two things.
	shared := sbom.VocabularyOverlap()
	if len(shared) > 0 {
		t.Errorf("two formats claim the same top-level key(s): %v", shared)
	}
}

func TestTheSecondFormatStatesItsRootThreeWays(t *testing.T) {
	// Two ways of pointing at it, and the case where several things are
	// pointed at. All three appear in the fixtures; pinned here because which
	// one a producer uses is its own business and a reader that handles one
	// looks correct against one fixture.
	describes := `{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "DESCRIBES"}`

	t.Run("by a relationship from the document", func(t *testing.T) {
		doc := read(t, minimalSPDX)
		if !doc.RootDeclared || doc.Root.Name != "product" {
			t.Errorf("root is %q, declared %v", doc.Root.Name, doc.RootDeclared)
		}
	})

	t.Run("by the same relationship stated backwards", func(t *testing.T) {
		body := strings.Replace(minimalSPDX, describes,
			`{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBED_BY"}`, 1)
		doc := read(t, body)
		if !doc.RootDeclared || doc.Root.Name != "product" {
			t.Errorf("root is %q, declared %v", doc.Root.Name, doc.RootDeclared)
		}
	})

	t.Run("by a list beside the packages", func(t *testing.T) {
		body := strings.Replace(minimalSPDX, describes,
			`{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "CONTAINS"}`, 1)
		body = strings.Replace(body, `"packages": [`, `"documentDescribes": ["SPDXRef-root"], "packages": [`, 1)
		doc := read(t, body)
		if !doc.RootDeclared || doc.Root.Name != "product" {
			t.Errorf("root is %q, declared %v", doc.Root.Name, doc.RootDeclared)
		}
	})

	t.Run("several things described leaves no root", func(t *testing.T) {
		// The tracked unit stands in. Picking one of them would be stating a
		// hierarchy the producer did not.
		body := strings.Replace(minimalSPDX, `"documentDescribes"`, `"unusedDescribes"`, 1)
		body = strings.Replace(body, `"packages": [`, `"documentDescribes": ["SPDXRef-root", "SPDXRef-a"], "packages": [`, 1)
		body = strings.Replace(body, describes, `{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "CONTAINS"}`, 1)
		doc := read(t, body)
		if doc.RootDeclared {
			t.Errorf("a document describing two things declared %q as its root", doc.Root.Name)
		}
		if len(doc.Components) != 2 {
			t.Errorf("read %d components, want 2 — neither is the root, so neither is held back", len(doc.Components))
		}
	})
}

func TestARelationshipStatedEitherWayRoundIsTheSameEdge(t *testing.T) {
	// A producer may say a program contains a library or that the library is
	// contained by the program, and the graph does not have two shapes.
	forward := `{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "%s"}`
	reverse := `{"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "%s"}`

	for _, tc := range []struct{ stated, body string }{
		{"CONTAINS", strings.Replace(forward, "%s", "CONTAINS", 1)},
		{"CONTAINED_BY", strings.Replace(reverse, "%s", "CONTAINED_BY", 1)},
		{"DEPENDS_ON", strings.Replace(forward, "%s", "DEPENDS_ON", 1)},
		{"DEPENDENCY_OF", strings.Replace(reverse, "%s", "DEPENDENCY_OF", 1)},
		{"DYNAMIC_LINK", strings.Replace(forward, "%s", "DYNAMIC_LINK", 1)},
		{"STATIC_LINK", strings.Replace(forward, "%s", "STATIC_LINK", 1)},
		{"HAS_PREREQUISITE", strings.Replace(forward, "%s", "HAS_PREREQUISITE", 1)},
		{"PREREQUISITE_FOR", strings.Replace(reverse, "%s", "PREREQUISITE_FOR", 1)},
		{"RUNTIME_DEPENDENCY_OF", strings.Replace(reverse, "%s", "RUNTIME_DEPENDENCY_OF", 1)},
		{"OPTIONAL_DEPENDENCY_OF", strings.Replace(reverse, "%s", "OPTIONAL_DEPENDENCY_OF", 1)},
		{"PROVIDED_DEPENDENCY_OF", strings.Replace(reverse, "%s", "PROVIDED_DEPENDENCY_OF", 1)},
	} {
		t.Run(tc.stated, func(t *testing.T) {
			body := strings.Replace(minimalSPDX,
				`{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "DEPENDS_ON"}`,
				tc.body, 1)
			doc := read(t, body)
			if got := edges(doc); !slices.Equal(got, []string{"product -> libc"}) {
				t.Errorf("edges are %v, want the library under the product", got)
			}
		})
	}
}

func TestWhatBuiltSomethingIsNotWhatItShipped(t *testing.T) {
	// The format states a hundred and forty kinds of relationship, and most of
	// them are not structure. A test dependency, a build tool and a thing that
	// generated a file are each a statement about the build rather than about
	// what is in the product — so none of them puts a component under another,
	// and the component is still held and still counted as sitting under
	// nothing.
	for _, kind := range []string{
		"BUILD_TOOL_OF", "DEV_TOOL_OF", "TEST_TOOL_OF", "TEST_DEPENDENCY_OF",
		"DEV_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "TEST_CASE_OF", "GENERATES",
		"GENERATED_FROM", "EXAMPLE_OF", "DOCUMENTATION_OF", "AMENDS", "OTHER",
	} {
		t.Run(kind, func(t *testing.T) {
			body := strings.Replace(minimalSPDX, `"relationshipType": "DEPENDS_ON"`,
				`"relationshipType": "`+kind+`"`, 1)
			doc := read(t, body)
			if len(doc.Dependencies) != 0 {
				t.Errorf("%s became %d edge(s)", kind, len(doc.Dependencies))
			}
			if len(doc.Components) != 1 {
				t.Errorf("read %d components, want 1 — the component still ships", len(doc.Components))
			}
			if doc.Unrooted != 1 {
				t.Errorf("%d components sit under nothing, want 1", doc.Unrooted)
			}
		})
	}
}

func TestWhatAComponentWasDerivedFromIsTakenFromAPointer(t *testing.T) {
	// The nearest this format comes to a pedigree. It can only name something
	// the document also describes, which is what makes it weaker than the
	// other format's — and it is still the difference between a finding that
	// can be explained and one that cannot.
	const ancestor = `{"SPDXID": "SPDXRef-upstream", "name": "openssl", "versionInfo": "3.0.14", "downloadLocation": "NONE"}`

	for _, tc := range []struct{ name, stated string }{
		{"ANCESTOR_OF", `{"spdxElementId": "SPDXRef-upstream", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "ANCESTOR_OF"}`},
		{"DESCENDANT_OF", `{"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-upstream", "relationshipType": "DESCENDANT_OF"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Replace(minimalSPDX, `"packages": [`, `"packages": [`+ancestor+`,`, 1)
			body = strings.Replace(body, `"relationships": [`, `"relationships": [`+tc.stated+`,`, 1)
			doc := read(t, body)
			var found bool
			for _, c := range doc.Components {
				if c.Name != "libc" {
					continue
				}
				found = true
				if c.UpstreamName != "openssl" || c.UpstreamVersion != "3.0.14" {
					t.Errorf("derived from %q@%q, want openssl@3.0.14", c.UpstreamName, c.UpstreamVersion)
				}
			}
			if !found {
				t.Error("the component the relationship was about is not in the document")
			}
		})
	}
}

func TestTheWordForNothingIsReadAsNothing(t *testing.T) {
	// The format requires several fields to be present and offers two words
	// for a producer with no value for one. Taken literally a package carries
	// the version "NOASSERTION", which a person reads as a version and a
	// scanner tries to match.
	body := strings.Replace(minimalSPDX, `"versionInfo": "2.41"`, `"versionInfo": "NOASSERTION"`, 1)
	body = strings.Replace(body, `"referenceLocator": "pkg:deb/debian/libc6@2.41"`, `"referenceLocator": "NONE"`, 1)
	doc := read(t, body)

	if len(doc.Components) != 1 {
		t.Fatalf("read %d components, want 1", len(doc.Components))
	}
	if got := doc.Components[0].Version; got != "" {
		t.Errorf("version is %q, want it read as unstated", got)
	}
	if got := doc.Components[0].Purl; got != "" {
		t.Errorf("package identifier is %q, want it read as unstated", got)
	}
	if doc.Unversioned != 1 {
		t.Errorf("%d components state no version, want 1 — it ships either way", doc.Unversioned)
	}
}

func TestTwoPackagesSharingOneIdentifierAreRefused(t *testing.T) {
	// Every edge naming it would be a coin toss. The same rule as the other
	// format's, against the identifier this one uses.
	body := strings.Replace(minimalSPDX, `"SPDXID": "SPDXRef-a"`, `"SPDXID": "SPDXRef-root"`, 1)
	if why := refuses(t, body); !strings.Contains(why, "share the identifier") {
		t.Errorf("refused with %q", why)
	}
}

func TestAPackageWithNoNameIsRefused(t *testing.T) {
	body := strings.Replace(minimalSPDX, `"name": "libc", `, "", 1)
	if why := refuses(t, body); !strings.Contains(why, "no name") {
		t.Errorf("refused with %q", why)
	}
}

func TestAnEdgeNamingAFileIsNotAnEdgeNamingNothing(t *testing.T) {
	// A format that catalogs files states most of its structure between a
	// package and the files it installed. Both are dropped; counting them
	// together would make a number meant to say the producer's derivation
	// changed move with how much file detail it was configured to emit.
	body := strings.Replace(minimalSPDX, `"packages": [`,
		`"files": [{"SPDXID": "SPDXRef-file", "fileName": "usr/lib/libc.so.6"}], "packages": [`, 1)
	body = strings.Replace(body, `"relationships": [`, `"relationships": [`+
		`{"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-file", "relationshipType": "CONTAINS"},`+
		`{"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-absent", "relationshipType": "CONTAINS"},`, 1)
	doc := read(t, body)

	if doc.FileReferences != 1 {
		t.Errorf("%d edges named a file, want 1", doc.FileReferences)
	}
	if doc.DanglingEdges != 1 {
		t.Errorf("%d edges named nothing, want 1", doc.DanglingEdges)
	}
	if len(doc.Components) != 1 {
		t.Errorf("read %d components, want 1 — a file is not one of them", len(doc.Components))
	}
}

func TestTheSecondFormatChargesTheSameBounds(t *testing.T) {
	// A bound that holds on one format and not the other is a bound somebody
	// routes around by changing which one they send.
	// A second package under the root, so that a bound of one edge has two to
	// count rather than one.
	twoEdges := strings.Replace(minimalSPDX, `"packages": [`,
		`"packages": [{"SPDXID": "SPDXRef-b", "name": "zlib", "versionInfo": "1.3", "downloadLocation": "NONE"},`, 1)
	twoEdges = strings.Replace(twoEdges, `"relationships": [`, `"relationships": [`+
		`{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-b", "relationshipType": "DEPENDS_ON"},`, 1)

	for _, tc := range []struct {
		name  string
		body  string
		limit sbom.Limits
		want  string
	}{
		{"components", minimalSPDX, sbom.Limits{MaxComponents: 1}, "component limit"},
		{"edges", twoEdges, sbom.Limits{MaxEdges: 1}, "dependency limit"},
		{"depth", minimalSPDX, sbom.Limits{MaxDepth: 2}, "level limit"},
		{"size", minimalSPDX, sbom.Limits{MaxBytes: 64}, "larger than the configured limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sbom.Read(strings.NewReader(tc.body), tc.limit)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused with %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestFilesAreBoundedApartFromComponents(t *testing.T) {
	// What a bound has to stop is the walk, and an unbounded array is an
	// unbounded walk whatever it holds. The bound is its own rather than the
	// component one because the two differ by a factor of fifty in a real
	// document: 4,964 files against 89 packages on one image, 21,643 against
	// 480 on another. Charged together, a switch operating system's inventory
	// in a format that catalogs files is refused at a ceiling that is right
	// for components.
	var b strings.Builder
	b.WriteString(`{"spdxVersion": "SPDX-2.3", "documentNamespace": "https://example.invalid/f", "files": [`)
	for i := range 50 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"SPDXID": "SPDXRef-f`)
		b.WriteString(string(rune('a' + i%26)))
		b.WriteString(`", "fileName": "a"}`)
	}
	b.WriteString(`]}`)

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxFiles: 10}); err == nil {
		t.Fatal("fifty files passed a bound of ten")
	} else if !strings.Contains(err.Error(), "file limit") {
		t.Errorf("refused with %q", err)
	}

	// And they do not spend the component bound. A document of fifty files and
	// no packages is not a document of fifty components.
	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 10}); err != nil {
		t.Errorf("fifty files spent a component bound of ten: %v", err)
	}
}

func TestReadsARealImageScan(t *testing.T) {
	// The scanner this deployment ships, emitting the second format for a
	// real image. What a hand-written document cannot stand in for: the root
	// stated as a relationship, one package carrying twelve spellings of the
	// database key, and five files cataloged for every package found.
	doc, err := sbom.Read(fixture(t, "alpine-image.spdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if doc.Root.Name != "alpine" || doc.Root.Version != "3.20" {
		t.Errorf("root is %q@%q", doc.Root.Name, doc.Root.Version)
	}
	if len(doc.Components) != 14 {
		t.Errorf("read %d components, want 14", len(doc.Components))
	}
	if len(doc.Dependencies) != 33 {
		t.Errorf("read %d edges, want 33", len(doc.Dependencies))
	}
	// The graph this producer states is almost all between a package and the
	// files it installed. None of it is an edge, and none of it is a hole.
	if doc.FileReferences != 77 {
		t.Errorf("%d edges named a file, want 77", doc.FileReferences)
	}
	if doc.DanglingEdges != 0 {
		t.Errorf("%d edges named nothing, want 0", doc.DanglingEdges)
	}
	if doc.Unrooted != 0 {
		t.Errorf("%d components sit under nothing, want 0", doc.Unrooted)
	}

	// Identity comes from the package identifier and the national database key
	// is kept beside it, exactly as it is for the other format. This producer
	// states both as external references of one package rather than as fields.
	var found bool
	for _, c := range doc.Components {
		if c.Name != "zlib" {
			continue
		}
		found = true
		if !strings.HasPrefix(c.Purl, "pkg:apk/alpine/zlib@") {
			t.Errorf("package identifier is %q", c.Purl)
		}
		if !strings.HasPrefix(c.CPE, "cpe:2.3:a:") {
			t.Errorf("database key is %q", c.CPE)
		}
	}
	if !found {
		t.Error("zlib is not in the document")
	}
}

func TestReadsTheFormatsOwnExamples(t *testing.T) {
	// The specification's own documents, which are what a producer is written
	// against. They state things the scanner does not: the root as a list
	// beside the packages, a package with no identifier at all, and a test
	// dependency that is in the document and not in the product.
	t.Run("a dependency graph with the root in a list", func(t *testing.T) {
		doc, err := sbom.Read(fixture(t, "rust-app.spdx.json"), sbom.Limits{})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		// The list names a package and a file built from it. One of the two is
		// something this tracks, which is what makes it the root.
		if doc.Root.Name != "hello-server-src" {
			t.Errorf("root is %q", doc.Root.Name)
		}
		if len(doc.Components) != 3 || len(doc.Dependencies) != 3 {
			t.Errorf("read %d components and %d edges, want 3 and 3", len(doc.Components), len(doc.Dependencies))
		}
	})

	t.Run("a document where most relationships are not structure", func(t *testing.T) {
		doc, err := sbom.Read(fixture(t, "maven-app.spdx.json"), sbom.Limits{})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if doc.Root.Name != "examplemaven" {
			t.Errorf("root is %q", doc.Root.Name)
		}
		// Eleven relationships, of which four put one component under another.
		if len(doc.Dependencies) != 4 {
			t.Errorf("read %d edges, want 4", len(doc.Dependencies))
		}
		// The test dependency is one of them. It ships in nothing, so it sits
		// under nothing — held and counted rather than dropped or attached to
		// the root on the assumption that it must be somewhere.
		if doc.Unrooted != 1 {
			t.Errorf("%d components sit under nothing, want 1 (JUnit)", doc.Unrooted)
		}
		// A producer that states no package identifier at all is ordinary.
		// What it costs is matching, and identity falls back to the name.
		if doc.Unversioned != 4 {
			t.Errorf("%d components state no version, want 4", doc.Unversioned)
		}
	})
}

func TestTheSameInventoryInEitherFormatReadsTheSame(t *testing.T) {
	// The point of a second format is that nothing downstream learns there is
	// one. Both documents describe one product with one library under it, and
	// what comes out of the reader has to be the same thing — same identity,
	// same graph — or a decision made against a build read one way lapses when
	// the build is read the other.
	first, second := read(t, minimal), read(t, minimalSPDX)

	if first.Root.Identity() != second.Root.Identity() {
		t.Errorf("roots are %q@%q and %q@%q",
			first.Root.Name, first.Root.Version, second.Root.Name, second.Root.Version)
	}
	if len(first.Components) != 1 || len(second.Components) != 1 {
		t.Fatalf("read %d and %d components, want 1 each", len(first.Components), len(second.Components))
	}
	// Identity is what a triage decision is attached to, so this is the
	// assertion the rest of them rest on.
	if first.Components[0].Identity() != second.Components[0].Identity() {
		t.Errorf("the same library reads as %q and %q",
			first.Components[0].Purl, second.Components[0].Purl)
	}
	if got, want := edges(second), edges(first); !slices.Equal(got, want) {
		t.Errorf("edges are %v and %v", want, got)
	}
}

func TestWhatTheSecondFormatCannotSay(t *testing.T) {
	// Pinned because it is a limit of the format rather than of the reader,
	// and a limit nothing states reads as an oversight.
	//
	// The other format carries a build's own claims about vulnerabilities it
	// has already answered, attached to the component they are about: a patch
	// in a pedigree naming what it fixes. This one has a relationship saying a
	// file is a patch for a package and no way at all to say which
	// vulnerability that patch resolves — so an inventory in this format
	// carries no claims, and a build with carried patches sends them in a
	// document of their own.
	doc := read(t, strings.Replace(minimalSPDX, `"relationships": [`, `"relationships": [`+
		`{"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-root", "relationshipType": "PATCH_APPLIED"},`, 1))

	if len(doc.Suppressions) != 0 {
		t.Errorf("read %d claims from a format that cannot state one", len(doc.Suppressions))
	}
	if len(doc.Dependencies) != 1 {
		t.Errorf("a patch relationship became structure: %v", edges(doc))
	}
}

func TestARootNamedTwiceIsStillOneRoot(t *testing.T) {
	// A format states the root in more than one place, and a producer that
	// fills in both has named one component twice. Counting the statements
	// rather than what they resolve to reads that as two roots and leaves the
	// document with none — so a document that says the same thing twice would
	// be read as though it had said nothing.
	body := strings.Replace(minimalSPDX, `"packages": [`,
		`"documentDescribes": ["SPDXRef-root"], "packages": [`, 1)
	doc := read(t, body)

	if !doc.RootDeclared || doc.Root.Name != "product" {
		t.Errorf("root is %q, declared %v", doc.Root.Name, doc.RootDeclared)
	}
	if len(doc.Components) != 1 {
		t.Errorf("read %d components, want 1 — the root is not among them", len(doc.Components))
	}
}

func TestHalfADeclarationIsNotADeclaration(t *testing.T) {
	// Either key alone leaves the other unstated, and an unstated version is a
	// version this was not written against. Both of these were refused before
	// a second format existed, and the refusal has to survive the dispatch
	// that made the two halves independent.
	for _, tc := range []struct{ name, body, want string }{{
		name: "a format with no version",
		body: `{"bomFormat": "CycloneDX", "components": [{"name": "libc"}]}`,
		want: "only half of what CycloneDX is: specVersion is missing",
	}, {
		name: "a version with no format",
		body: `{"specVersion": "1.6", "components": [{"name": "libc"}]}`,
		want: "only half of what CycloneDX is: bomFormat is missing",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if why := refuses(t, tc.body); !strings.Contains(why, tc.want) {
				t.Errorf("refused with %q, want it to mention %q", why, tc.want)
			}
		})
	}
}

func TestADocumentStatingTwoFormatsIsRefused(t *testing.T) {
	// A handler writes to the document before anything has checked what the
	// document is, and both formats state an identity — so a file carrying
	// both keys is stored under whichever came last, which is a different
	// identity for the same bytes depending only on how its producer sorted
	// them. Refused rather than preferred: nothing here can say which half the
	// producer meant.
	both := `{"bomFormat": "CycloneDX", "specVersion": "1.6",
	  "serialNumber": "urn:uuid:1", "documentNamespace": "https://example.invalid/2",
	  "components": [{"name": "libc"}]}`
	if why := refuses(t, both); !strings.Contains(why, "states both CycloneDX 1.x and SPDX 2.x") {
		t.Errorf("refused with %q", why)
	}

	// And the same file with the two identity keys the other way round is
	// refused identically, which is the property that matters.
	swapped := `{"bomFormat": "CycloneDX", "specVersion": "1.6",
	  "documentNamespace": "https://example.invalid/2", "serialNumber": "urn:uuid:1",
	  "components": [{"name": "libc"}]}`
	if why := refuses(t, swapped); !strings.Contains(why, "states both CycloneDX 1.x and SPDX 2.x") {
		t.Errorf("refused with %q", why)
	}
}

func TestARealThirdVersionDocumentIsNeverRefusedAsUnrecognized(t *testing.T) {
	// The third version states a document as a context and one linked graph,
	// with no `spdxVersion` anywhere. Before it was read, the by-name refusal
	// hung off a second-version key and so could never fire on one, and the
	// document landed in "it is neither" — which sends whoever reads it
	// hunting for a corrupt file. It is not corrupt, and now it is read.
	//
	// Kept pointing at that message rather than deleted, because the way to
	// reintroduce the fault is to stop claiming its keys, and then this is the
	// message that comes back.
	real3 := `{
	  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
	  "@graph": [
	    {"spdxId": "urn:a", "type": "software_Package", "name": "libc",
	     "software_packageVersion": "2.41"}
	  ]}`
	doc, err := sbom.Read(strings.NewReader(real3), sbom.Limits{})
	if err != nil {
		t.Fatalf("a well-formed document of a format this reads was refused: %v", err)
	}
	if len(doc.Components) != 1 {
		t.Errorf("read %d components, want 1", len(doc.Components))
	}
	if doc.Format != sbom.SPDX {
		t.Errorf("format is %q, want %q", doc.Format, sbom.SPDX)
	}
}

func TestTheWordForNothingIsNothingAtAnEdgesEnds(t *testing.T) {
	// "Contains nothing" is a statement the format lets a producer make. Read
	// literally it is an identifier nothing describes, so the edge is charged
	// and then lands in the count that says the producer's derivation changed.
	body := strings.Replace(minimalSPDX,
		`{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "DEPENDS_ON"}`,
		`{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "NONE", "relationshipType": "CONTAINS"},`+
			`{"spdxElementId": "NOASSERTION", "relatedSpdxElement": "SPDXRef-a", "relationshipType": "CONTAINS"}`, 1)
	doc := read(t, body)

	if doc.DanglingEdges != 0 {
		t.Errorf("%d edges named nothing, want 0 — saying so is not a hole in the graph", doc.DanglingEdges)
	}
	if len(doc.Dependencies) != 0 {
		t.Errorf("read %d edges from two statements about nothing", len(doc.Dependencies))
	}
}

func TestAFileAndAComponentMayNotShareAnIdentifier(t *testing.T) {
	// Two components sharing one is refused because every edge naming it is a
	// coin toss. Across the two arrays the toss is worse, not better: the edge
	// resolves to the package and invents a dependency the producer never
	// stated. Refused whichever array the format puts first.
	afterwards := strings.Replace(minimalSPDX, `"packages": [`,
		`"files": [{"SPDXID": "SPDXRef-a", "fileName": "usr/lib/libc.so.6"}], "packages": [`, 1)
	if why := refuses(t, afterwards); !strings.Contains(why, "file and a component share the identifier") {
		t.Errorf("refused with %q", why)
	}

	before := strings.Replace(minimalSPDX, `"relationships": [`,
		`"files": [{"SPDXID": "SPDXRef-a", "fileName": "usr/lib/libc.so.6"}], "relationships": [`, 1)
	if why := refuses(t, before); !strings.Contains(why, "file and a component share the identifier") {
		t.Errorf("refused with %q", why)
	}
}

func TestAStatedAncestorRefinesOneTakenFromAnIdentifier(t *testing.T) {
	// Where no pedigree is stated the upstream name comes from the package
	// identifier, which carries a name and no version in most cases — and the
	// version is what expiry compares. A pointer naming a package the document
	// fully describes knows the version, so it fills that in rather than
	// losing to a half-answer.
	body := strings.Replace(minimalSPDX,
		`"referenceLocator": "pkg:deb/debian/libc6@2.41"`,
		`"referenceLocator": "pkg:deb/debian/libc6@2.41?upstream=glibc"`, 1)
	body = strings.Replace(body, `"packages": [`,
		`"packages": [{"SPDXID": "SPDXRef-up", "name": "glibc", "versionInfo": "2.41-9", "downloadLocation": "NONE"},`, 1)
	body = strings.Replace(body, `"relationships": [`, `"relationships": [`+
		`{"spdxElementId": "SPDXRef-a", "relatedSpdxElement": "SPDXRef-up", "relationshipType": "DESCENDANT_OF"},`, 1)

	doc := read(t, body)
	var found bool
	for _, c := range doc.Components {
		if c.Name != "libc" {
			continue
		}
		found = true
		if c.UpstreamName != "glibc" {
			t.Errorf("derived from %q, want glibc", c.UpstreamName)
		}
		if c.UpstreamVersion != "2.41-9" {
			t.Errorf("derived from version %q, want 2.41-9 — the identifier states no version", c.UpstreamVersion)
		}
	}
	if !found {
		t.Error("the component the relationship was about is not in the document")
	}
}

func TestADerivationIsChargedAgainstTheClaimBound(t *testing.T) {
	// The only thing bounding what a document may say one component was
	// derived from. Nothing else in the reader charges this, so without it a
	// relationships array of derivations fills a map under the byte cap alone.
	var b strings.Builder
	b.WriteString(`{"spdxVersion": "SPDX-2.3", "documentNamespace": "https://example.invalid/d",
	  "packages": [{"SPDXID": "SPDXRef-a", "name": "libc", "downloadLocation": "NONE"},
	               {"SPDXID": "SPDXRef-b", "name": "zlib", "downloadLocation": "NONE"}],
	  "relationships": [`)
	for i, ref := range []string{"SPDXRef-a", "SPDXRef-b"} {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"spdxElementId": "` + ref + `", "relatedSpdxElement": "SPDXRef-a",` +
			` "relationshipType": "DESCENDANT_OF"}`)
	}
	b.WriteString(`]}`)

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxStatements: 1}); err == nil {
		t.Fatal("two derivations passed a bound of one")
	} else if !strings.Contains(err.Error(), "claim limit") {
		t.Errorf("refused with %q", err)
	}
}

func TestWhatTheDocumentSaysItIsAboutIsBounded(t *testing.T) {
	// A top-level array of references, read on the header pass that runs
	// inside the upload request. It was the one array with neither a skip
	// above it nor a bound in it.
	var b strings.Builder
	b.WriteString(`{"spdxVersion": "SPDX-2.3", "documentDescribes": [`)
	for i := range 50 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"SPDXRef-a"`)
	}
	b.WriteString(`]}`)

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 10}); err == nil {
		t.Fatal("fifty references passed a bound of ten")
	} else if !strings.Contains(err.Error(), "component limit") {
		t.Errorf("refused with %q", err)
	}

	// And the header pass walks past them rather than holding them, since it
	// resolves no root.
	header, err := sbom.ReadHeader(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 10})
	if err != nil {
		t.Fatalf("a header read charged a bound for something it does not keep: %v", err)
	}
	if header.RootDeclared {
		t.Error("a header-only read resolved a root")
	}
}

func TestARootStatedByRelationshipIsBoundedToo(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"spdxVersion": "SPDX-2.3", "relationships": [`)
	for i := range 50 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-a",` +
			` "relationshipType": "DESCRIBES"}`)
	}
	b.WriteString(`]}`)

	if _, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxEdges: 10}); err == nil {
		t.Fatal("fifty statements passed a bound of ten")
	} else if !strings.Contains(err.Error(), "dependency limit") {
		t.Errorf("refused with %q", err)
	}
}

func TestTheFormatADocumentDeclaredIsCarriedOut(t *testing.T) {
	// One thing downstream needs it: the formats do not state the same facts,
	// so a scan saying nothing about carried patches has either withdrawn them
	// or been unable to repeat them, and those are not the same event.
	if got := read(t, minimal).Format; got != sbom.CycloneDX {
		t.Errorf("format is %q, want %q", got, sbom.CycloneDX)
	}
	if got := read(t, minimalSPDX).Format; got != sbom.SPDX {
		t.Errorf("format is %q, want %q", got, sbom.SPDX)
	}
	if !sbom.CycloneDX.StatesCarriedPatches() {
		t.Error("CycloneDX attaches a claim to the component it is about")
	}
	if sbom.SPDX.StatesCarriedPatches() {
		t.Error("SPDX cannot say which vulnerability a patch resolves")
	}
}
