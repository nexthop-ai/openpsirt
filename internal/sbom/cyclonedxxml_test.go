// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// minimalXML is minimal, encoded as XML.
const minimalXML = `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6">
  <metadata><component type="application" bom-ref="root"><name>product</name><version>1.0</version></component></metadata>
  <components>
    <component type="library" bom-ref="a"><name>libc</name><version>2.41</version><purl>pkg:deb/debian/libc6@2.41</purl></component>
  </components>
  <dependencies><dependency ref="root"><dependency ref="a"/></dependency></dependencies>
</bom>`

// sameDocument fails the test for every part of two documents that differs.
// Two encodings of one inventory have to read as one inventory down to the
// counts, or a decision made against a build read one way lapses when it is
// read the other.
func sameDocument(t *testing.T, json, xml *sbom.Document) {
	t.Helper()
	a, b := reflect.ValueOf(*json), reflect.ValueOf(*xml)
	for i := range a.NumField() {
		if !reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
			t.Errorf("%s differs:\n  JSON: %+v\n  XML:  %+v",
				a.Type().Field(i).Name, a.Field(i).Interface(), b.Field(i).Interface())
		}
	}
}

// eachDescribed calls fn with every component a document holds, wherever it
// holds one.
func eachDescribed(doc *sbom.Document, fn func(*graph.Described)) {
	fn(&doc.Root)
	for i := range doc.Components {
		fn(&doc.Components[i])
	}
	for i := range doc.Dependencies {
		fn(&doc.Dependencies[i].Parent)
		fn(&doc.Dependencies[i].Child)
	}
}

func TestEachEncodingOfOneProducersInventoryReadsTheSame(t *testing.T) {
	// The Maven plugin writes both encodings side by side, and these are one
	// build's two: it is the producer most likely to send XML. The image is
	// the hand-written one in both, because it is the only fixture carrying a
	// pedigree, a carried patch and a supplier.
	for _, pair := range []struct {
		json, xml string
		// published reconciles what the producer wrote differently in the
		// two, asserting each difference is there first, so that what is left
		// to compare is the reader and nothing else.
		published func(t *testing.T, xml *sbom.Document)
	}{
		{json: "maven-dropwizard.cdx.json", xml: "maven-dropwizard.cdx.xml",
			published: func(t *testing.T, xml *sbom.Document) {
				// The plugin did not write one build the same way twice. Its XML
				// states a scope on every component and its JSON on none, so
				// every edge the XML reads says "required" and none the JSON
				// reads says anything.
				for i, d := range xml.Dependencies {
					if d.Kind != "required" {
						t.Errorf("an edge into %s says %q, and the XML states every scope as required",
							d.Child.Name, d.Kind)
					}
					xml.Dependencies[i].Kind = ""
				}
				// And its XML leaves out the one license its JSON states as an
				// expression.
				const name, license = "osgi-resource-locator", "(CDDL-1.0 OR GPL-2.0-with-classpath-exception)"
				found := false
				eachDescribed(xml, func(d *graph.Described) {
					if d.Name != name {
						return
					}
					found = true
					if d.License != "" {
						t.Errorf("%s states the license %q in XML, which the published file does not", name, d.License)
					}
					d.License = license
				})
				if !found {
					t.Errorf("no %s was read from the XML", name)
				}
			}},
		{json: "image.cdx.json", xml: "image.cdx.xml"},
	} {
		t.Run(pair.xml, func(t *testing.T) {
			json, err := sbom.Read(fixture(t, pair.json), sbom.DefaultLimits())
			if err != nil {
				t.Fatalf("read %s: %v", pair.json, err)
			}
			xml, err := sbom.Read(fixture(t, pair.xml), sbom.DefaultLimits())
			if err != nil {
				t.Fatalf("read %s: %v", pair.xml, err)
			}
			if len(xml.Components) == 0 || len(xml.Dependencies) == 0 {
				t.Fatalf("read %d components and %d edges, so nothing was compared",
					len(xml.Components), len(xml.Dependencies))
			}
			if pair.published != nil {
				pair.published(t, xml)
			}
			sameDocument(t, json, xml)

			jsonHeader, err := sbom.ReadHeader(fixture(t, pair.json), sbom.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			xmlHeader, err := sbom.ReadHeader(fixture(t, pair.xml), sbom.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(jsonHeader, xmlHeader) {
				t.Errorf("headers are %+v and %+v", jsonHeader, xmlHeader)
			}
		})
	}
}

func TestWhatNoFixtureCarriesReadsTheSameInEitherEncoding(t *testing.T) {
	// The spellings neither fixture pair has: a license expression, a license
	// marked as concluded either way the format allows, components nested in
	// a component and in the root, both ways of naming a supplier, and a
	// scope.
	const json = `{"bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "root", "name": "product", "version": "1.0",
    "components": [{"bom-ref": "agent", "name": "agent", "version": "2.0", "purl": "pkg:generic/agent@2.0"}]}},
  "components": [
    {"bom-ref": "a", "name": "openssl", "version": "3.0.13", "purl": "pkg:deb/debian/openssl@3.0.13",
     "publisher": "Debian", "scope": "optional",
     "licenses": [{"expression": "Apache-2.0 OR MIT"}],
     "components": [{"bom-ref": "a1", "name": "libcrypto", "version": "3.0.13", "purl": "pkg:deb/debian/libcrypto3@3.0.13",
       "licenses": [{"license": {"name": "OpenSSL License", "acknowledgement": "concluded"}}, {"license": {"id": "Apache-2.0"}}]}]},
    {"bom-ref": "b", "name": "zlib", "version": "1.3", "purl": "pkg:deb/debian/zlib1g@1.3",
     "supplier": {"name": "zlib project"}, "publisher": "someone else", "scope": "excluded",
     "licenses": [{"expression": "Zlib", "acknowledgement": "concluded"}]}
  ],
  "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}]
}`
	const xml = `<bom xmlns="http://cyclonedx.org/schema/bom/1.6">
  <metadata><component type="application" bom-ref="root"><name>product</name><version>1.0</version>
    <components><component type="application" bom-ref="agent"><name>agent</name><version>2.0</version><purl>pkg:generic/agent@2.0</purl></component></components>
  </component></metadata>
  <components>
    <component type="library" bom-ref="a">
      <publisher>Debian</publisher><name>openssl</name><version>3.0.13</version><scope>optional</scope>
      <licenses><expression>Apache-2.0 OR MIT</expression></licenses>
      <purl>pkg:deb/debian/openssl@3.0.13</purl>
      <components>
        <component type="library" bom-ref="a1"><name>libcrypto</name><version>3.0.13</version>
          <licenses>
            <license acknowledgement="concluded"><name>OpenSSL License</name></license>
            <license><id>Apache-2.0</id></license>
          </licenses>
          <purl>pkg:deb/debian/libcrypto3@3.0.13</purl>
        </component>
      </components>
    </component>
    <component type="library" bom-ref="b">
      <supplier><name>zlib project</name></supplier><publisher>someone else</publisher>
      <name>zlib</name><version>1.3</version><scope>excluded</scope>
      <licenses><expression acknowledgement="concluded">Zlib</expression></licenses>
      <purl>pkg:deb/debian/zlib1g@1.3</purl>
    </component>
  </components>
  <dependencies><dependency ref="root"><dependency ref="a"/><dependency ref="b"/></dependency></dependencies>
</bom>`

	first, second := read(t, json), read(t, xml)
	sameDocument(t, first, second)

	// And what the two agree on is what was written, so that agreeing on
	// nothing does not pass.
	byName := map[string]string{}
	for _, c := range second.Components {
		byName[c.Name] = c.License + " / " + c.Supplier
	}
	for name, want := range map[string]string{
		"openssl":   "Apache-2.0 OR MIT / Debian",
		"libcrypto": "Apache-2.0 / ",
		"zlib":      "Zlib / zlib project",
		"agent":     " / ",
	} {
		if byName[name] != want {
			t.Errorf("%s reads as %q, want %q", name, byName[name], want)
		}
	}
	got := map[string]string{}
	for _, d := range second.Dependencies {
		got[d.Parent.Name+" -> "+d.Child.Name] = d.Kind
	}
	for edge, kind := range map[string]string{
		"product -> agent": "", "product -> openssl": "optional",
		"product -> zlib": "excluded", "openssl -> libcrypto": "",
	} {
		if have, ok := got[edge]; !ok || have != kind {
			t.Errorf("edge %s is %q (present: %v), want %q", edge, have, ok, kind)
		}
	}
}

func TestADocumentTypeDeclarationIsRefusedWhereverItIs(t *testing.T) {
	// The declaration is refused as it is met, before anything it defines can
	// be used: an entity naming a file or a URL, one expanding into a billion
	// copies of another, or a declaration that only points somewhere.
	for name, body := range map[string]string{
		"an external entity naming a file": `<?xml version="1.0"?>
<!DOCTYPE bom [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component><name>&x;</name></component></components></bom>`,
		"an external entity naming a URL": `<!DOCTYPE bom [<!ENTITY x SYSTEM "http://example.invalid/x">]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><metadata><timestamp>&x;</timestamp></metadata></bom>`,
		"a parameter entity": `<!DOCTYPE bom [<!ENTITY % p SYSTEM "http://example.invalid/p.dtd"> %p;]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>`,
		"entities expanding into each other": `<!DOCTYPE bom [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><components><component><name>&c;</name></component></components></bom>`,
		"an external declaration alone": `<!DOCTYPE bom SYSTEM "http://example.invalid/bom.dtd">
<bom xmlns="http://cyclonedx.org/schema/bom/1.6"/>`,
		"a declaration inside the document": `<bom xmlns="http://cyclonedx.org/schema/bom/1.6"><!DOCTYPE bom></bom>`,
	} {
		t.Run(name, func(t *testing.T) {
			for what, err := range map[string]error{
				"read":        func() error { _, err := sbom.Read(strings.NewReader(body), sbom.Limits{}); return err }(),
				"header read": func() error { _, err := sbom.ReadHeader(strings.NewReader(body), sbom.Limits{}); return err }(),
			} {
				if !refusal.In(err) || !strings.Contains(err.Error(), "document type declaration") {
					t.Errorf("%s answered %v, want a refusal naming the declaration", what, err)
				}
			}
		})
	}
}

func TestAnXMLDocumentIsRefusedForWhatXMLForbids(t *testing.T) {
	// Refused rather than repaired. The JSON reader drops a NUL it meets,
	// because JSON allows one; XML does not, so a document carrying one is not
	// XML.
	for name, body := range map[string]string{
		"an entity it never defines": strings.Replace(minimalXML, "<name>libc</name>", "<name>&x;</name>", 1),
		"a NUL":                      strings.Replace(minimalXML, "<name>libc</name>", "<name>li\x00bc</name>", 1),
		"a NUL by reference":         strings.Replace(minimalXML, "<name>libc</name>", "<name>li&#0;bc</name>", 1),
		"an encoding other than UTF-8": strings.Replace(minimalXML,
			`encoding="UTF-8"`, `encoding="ISO-8859-1"`, 1),
		"an element where text belongs": strings.Replace(minimalXML,
			"<name>libc</name>", "<name><b>libc</b></name>", 1),
		"no end": strings.TrimSuffix(minimalXML, "</bom>"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sbom.Read(strings.NewReader(body), sbom.Limits{}); !refusal.In(err) {
				t.Errorf("answered %v, want a refusal", err)
			}
		})
	}
}

func TestWhatTheDecoderSaysIsQuotedBounded(t *testing.T) {
	// The decoder says what is wrong with a document by quoting it, and the
	// refusal goes back to whoever sent it: a megabyte of name came back as a
	// megabyte of refusal.
	long := strings.Repeat("a", 1<<20)
	for name, body := range map[string]string{
		"an element closed by another": strings.Replace(minimalXML,
			"<components>", "<components><"+long+"></b>", 1),
		"an entity it never defines": strings.Replace(minimalXML,
			"<name>libc</name>", "<name>&"+long+";</name>", 1),
		"the encoding it declares": strings.Replace(minimalXML,
			`encoding="UTF-8"`, `encoding="`+long+`"`, 1),
		"the version it declares": strings.Replace(minimalXML,
			`version="1.0"`, `version="`+long+`"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sbom.Read(strings.NewReader(body), sbom.DefaultLimits())
			if !refusal.In(err) {
				t.Fatalf("answered %v, want a refusal", err)
			}
			if n := len(err.Error()); n > 1024 {
				t.Errorf("refused in %d bytes for a document of %d", n, len(body))
			}
		})
	}
}

func TestAnXMLDocumentContinuingAfterItsTopLevelElementIsRefused(t *testing.T) {
	// The decoder reads a second top-level element as readily as the first.
	for name, body := range map[string]string{
		"a second document":          minimalXML + minimalXML,
		"text":                       minimalXML + "\nand then some",
		"a stray element":            minimalXML + "<component/>",
		"a processing instruction":   minimalXML + "\n<?producer said more?>",
		"a declaration after it all": minimalXML + "\n<!DOCTYPE bom>",
		// After the declaration, so the document still opens with an angle
		// bracket and is read as XML: opening with the text would send it to
		// the JSON reader instead.
		"text before the top": strings.Replace(minimalXML, "?>\n<bom", "?>a<bom", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sbom.Read(strings.NewReader(body), sbom.Limits{}); !refusal.In(err) {
				t.Errorf("read answered %v, want a refusal", err)
			}
			if _, err := sbom.ReadHeader(strings.NewReader(body), sbom.Limits{}); !refusal.In(err) {
				t.Errorf("header read answered %v, want a refusal", err)
			}
		})
	}
	// Layout and comments after it are not content.
	read(t, minimalXML+"\n<!-- written by hand -->\n")
}

func TestOnlyCycloneDXIsReadAsXML(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"SPDX's RDF encoding": {
			`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:spdx="http://spdx.org/rdf/terms#"/>`,
			"only CycloneDX is read as XML",
		},
		"a document in no namespace": {
			`<bom><components/></bom>`, "only CycloneDX is read as XML",
		},
		"a second major version": {
			`<bom xmlns="http://cyclonedx.org/schema/bom/2.0"/>`, `version "2.0" is not one this reads`,
		},
		// The namespace is half of what the top-level element says. An element
		// of the format's own that is not a document is not one.
		"another of the format's elements at the top": {
			`<component xmlns="http://cyclonedx.org/schema/bom/1.6"><name>libc</name></component>`,
			"only CycloneDX is read as XML",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sbom.Read(strings.NewReader(tc.body), sbom.Limits{})
			if !refusal.In(err) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("answered %v, want a refusal mentioning %q", err, tc.want)
			}
		})
	}
}

func TestEveryCycloneDXRevisionIsReadAsXML(t *testing.T) {
	// The revisions seen in the sample of public inventories, and the last.
	for _, revision := range []string{"1.1", "1.2", "1.5", "1.6", "1.7"} {
		t.Run(revision, func(t *testing.T) {
			doc := read(t, strings.Replace(minimalXML, "bom/1.6", "bom/"+revision, 1))
			if doc.Format != sbom.CycloneDX || len(doc.Components) != 1 {
				t.Errorf("read as %q with %d components", doc.Format, len(doc.Components))
			}
		})
	}
}

func TestAnElementInAnotherNamespaceIsNotRead(t *testing.T) {
	// An extension may name its elements as it likes, and one called
	// "component" is still not a component of the format's.
	doc := read(t, `<bom xmlns="http://cyclonedx.org/schema/bom/1.6" xmlns:x="urn:example:extension">
  <components>
    <component type="library" bom-ref="a"><name>libc</name><x:name>not its name</x:name><version>2.41</version></component>
    <x:component><x:name>not a component</x:name></x:component>
  </components>
</bom>`)
	if len(doc.Components) != 1 || doc.Components[0].Name != "libc" {
		t.Errorf("read %+v", doc.Components)
	}
	// And a document whose own elements carry a prefix is the same document.
	prefixed := read(t, `<c:bom xmlns:c="http://cyclonedx.org/schema/bom/1.6">
  <c:components><c:component type="library"><c:name>libc</c:name><c:version>2.41</c:version></c:component></c:components>
</c:bom>`)
	if len(prefixed.Components) != 1 || prefixed.Components[0].Name != "libc" {
		t.Errorf("read %+v", prefixed.Components)
	}
}

func TestADocumentOpeningWithAByteOrderMarkIsRead(t *testing.T) {
	// cyclonedx-dotnet writes one, as .NET does by default.
	sameDocument(t, read(t, minimalXML), read(t, "\xef\xbb\xbf"+minimalXML))
}

func TestXMLChargesTheSameBounds(t *testing.T) {
	// A bound that holds on one encoding and not the other is a bound somebody
	// routes around by changing which one they send.
	twoEdges := strings.Replace(minimalXML, `<dependency ref="a"/>`,
		`<dependency ref="a"/><dependency ref="a"/>`, 1)
	// A dependency nested in a nested one is an edge too, and charged.
	nestedEdges := strings.Replace(minimalXML, `<dependency ref="a"/>`,
		`<dependency ref="a"><dependency ref="root"/></dependency>`, 1)
	licenses := strings.Replace(minimalXML, `<name>product</name>`,
		`<name>product</name><licenses>`+strings.Repeat(`<license><id>MIT</id></license>`, 21)+`</licenses>`, 1)
	claims := strings.Replace(minimalXML, `<purl>pkg:deb/debian/libc6@2.41</purl>`,
		`<purl>pkg:deb/debian/libc6@2.41</purl><pedigree><patches><patch type="backport"><resolves>`+
			`<issue type="security"><id>CVE-2026-0001</id></issue><issue type="security"><id>CVE-2026-0002</id></issue>`+
			`</resolves></patch></patches></pedigree>`, 1)
	// Nested in an extension, which is walked past rather than read. The rest
	// of the document is no deeper than four, so it is the walk past that the
	// bound has to stop.
	unread := strings.Replace(minimalXML, "<components>", `<x:e xmlns:x="urn:x">`+
		strings.Repeat("<x:e>", 5)+strings.Repeat("</x:e>", 5)+"</x:e><components>", 1)

	for _, tc := range []struct {
		name  string
		body  string
		limit sbom.Limits
		want  string
	}{
		{"components", minimalXML, sbom.Limits{MaxComponents: 1}, "component limit"},
		{"edges", twoEdges, sbom.Limits{MaxEdges: 1}, "dependency limit"},
		{"nested edges", nestedEdges, sbom.Limits{MaxEdges: 1}, "dependency limit"},
		{"depth", minimalXML, sbom.Limits{MaxDepth: 2}, "level limit"},
		{"depth in an element nothing reads", unread, sbom.Limits{MaxDepth: 4}, "level limit"},
		{"size", minimalXML, sbom.Limits{MaxBytes: 64}, "larger than the configured limit"},
		{"licenses", licenses, sbom.Limits{MaxComponents: 2}, "license entries"},
		{"claims", claims, sbom.Limits{MaxStatements: 1}, "claim limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sbom.Read(strings.NewReader(tc.body), tc.limit)
			if !refusal.In(err) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("answered %v, want a refusal mentioning %q", err, tc.want)
			}
		})
	}
}

func TestAnXMLHeaderReadHoldsNothingItWalkedPast(t *testing.T) {
	// The header read runs inside the upload request. The components nested
	// in the root are walked and charged, and none of them kept.
	body := strings.Replace(minimalXML, `<version>1.0</version>`, `<version>1.0</version><components>`+
		strings.Repeat(`<component type="library"><name>x</name><version>1</version></component>`, 5)+
		`</components>`, 1)
	bound, contained, members, scopes, claims, err := sbom.HeaderHeld(body, sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if bound+contained+members+scopes+claims != 0 {
		t.Errorf("held %d bound, %d contained, %d members, %d scopes, %d claims",
			bound, contained, members, scopes, claims)
	}
	if _, err := sbom.ReadHeader(strings.NewReader(body), sbom.Limits{MaxComponents: 5}); !refusal.In(err) {
		t.Errorf("a header read past the component bound answered %v, want a refusal", err)
	}
}

// failingOnce hands over its bytes, fails once with err, and then reports the
// end of the document. Only whatever read the failure can know of it, so a
// caller that drops it reads a document that merely ends early.
type failingOnce struct {
	r      io.Reader
	err    error
	failed bool
}

func (f *failingOnce) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if errors.Is(err, io.EOF) && !f.failed {
		f.failed = true
		return n, f.err
	}
	return n, err
}

func TestAnXMLReaderThatFailsPartwayIsAFaultNotARefusal(t *testing.T) {
	// Short enough that the failure is met while the first character is
	// looked at, which buffers ahead of the walk.
	partial := minimalXML[:strings.Index(minimalXML, "<dependencies>")+20]
	// Long enough that it is met by the walk instead.
	padded := strings.Replace(partial, "<metadata>",
		"<!-- "+strings.Repeat("layout ", 1200)+"--><metadata>", 1)
	cause := errors.New("the document was let go while it was read")
	for name, r := range map[string]func() io.Reader{
		"before the first character": func() io.Reader {
			return &failing{r: strings.NewReader(""), err: cause}
		},
		"while the first character is looked at": func() io.Reader {
			return &failingOnce{r: strings.NewReader(partial), err: cause}
		},
		"during the walk": func() io.Reader {
			return &failingOnce{r: strings.NewReader(padded), err: cause}
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sbom.Read(r(), sbom.Limits{})
			if !errors.Is(err, cause) || refusal.In(err) {
				t.Errorf("answered %v, want the fault itself", err)
			}
		})
	}
	for _, body := range []string{partial, padded} {
		if _, err := sbom.Read(strings.NewReader(body), sbom.Limits{}); !refusal.In(err) {
			t.Errorf("a document of %d bytes ending partway on its own answered %v, want a refusal",
				len(body), err)
		}
	}
}
