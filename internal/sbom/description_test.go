// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/bound"
)

// describedAs reads a document and answers what it says each component is, by
// name.
func describedAs(t *testing.T, body string) map[string]string {
	t.Helper()
	said := map[string]string{}
	for _, c := range read(t, body).Components {
		said[c.Name] = c.Description
	}
	return said
}

// A generic package's description is all a reader is told about it, so each
// encoding of the first format reads it, on one line and without what a
// screen cannot draw.
func TestAComponentsDescriptionIsReadInEitherEncodingOnOneLine(t *testing.T) {
	const json = `{"bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "root", "name": "product", "version": "1.0"}},
  "components": [
    {"bom-ref": "a", "name": "option-rom-0x8086-0x1533-x86-legacy", "version": "1.5.89",
     "purl": "pkg:generic/option-rom-0x8086-0x1533-x86-legacy@1.5.89",
     "description": "Intel Boot Agent v1.5.89 (x86 legacy)\n  for Intel I210\u001b[0m Gigabit Network Connection"},
    {"bom-ref": "b", "name": "silent", "version": "1", "purl": "pkg:generic/silent@1"}
  ],
  "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}]
}`
	const xml = `<bom xmlns="http://cyclonedx.org/schema/bom/1.6">
  <metadata><component type="application" bom-ref="root"><name>product</name><version>1.0</version></component></metadata>
  <components>
    <component type="firmware" bom-ref="a">
      <name>option-rom-0x8086-0x1533-x86-legacy</name><version>1.5.89</version>
      <description>Intel Boot Agent v1.5.89 (x86 legacy)
        for Intel I210&#x9;Gigabit Network Connection</description>
      <purl>pkg:generic/option-rom-0x8086-0x1533-x86-legacy@1.5.89</purl>
    </component>
    <component type="library" bom-ref="b"><name>silent</name><version>1</version><purl>pkg:generic/silent@1</purl></component>
  </components>
  <dependencies><dependency ref="root"><dependency ref="a"/><dependency ref="b"/></dependency></dependencies>
</bom>`
	for _, tc := range []struct{ name, body, want string }{
		{"JSON", json, "Intel Boot Agent v1.5.89 (x86 legacy) for Intel I210[0m Gigabit Network Connection"},
		{"XML", xml, "Intel Boot Agent v1.5.89 (x86 legacy) for Intel I210 Gigabit Network Connection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			said := describedAs(t, tc.body)
			if got := said["option-rom-0x8086-0x1533-x86-legacy"]; got != tc.want {
				t.Errorf("the option ROM is described as %q, want %q", got, tc.want)
			}
			if got := said["silent"]; got != "" {
				t.Errorf("a component stating nothing is described as %q", got)
			}
		})
	}
}

// A description is held while the document is read, so it is cut as it is
// read: a document of long descriptions holds a line of each.
func TestADescriptionIsCutAsItIsRead(t *testing.T) {
	long := strings.Repeat("界", bound.MostLine*4)
	said := describedAs(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "root", "name": "product", "version": "1.0"}},
  "components": [{"bom-ref": "a", "name": "long", "version": "1", "description": "`+long+`"}],
  "dependencies": [{"ref": "root", "dependsOn": ["a"]}]
}`)
	got := said["long"]
	if n := utf8.RuneCountInString(got); n != bound.MostLine || !utf8.ValidString(got) {
		t.Errorf("a long description is read at %d characters, valid %t, want %d",
			n, utf8.ValidString(got), bound.MostLine)
	}
}

// The second format states a short summary and a long description. The page
// shows one line, which is what the summary is for, so it wins whichever order
// the producer wrote them in, and the description stands where it is alone.
func TestASecondFormatPackagesSummaryBeatsItsDescription(t *testing.T) {
	document := func(fields string) string {
		return `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "x",
		 "creationInfo": {"created": "2026-09-01T00:00:00Z"},
		 "documentDescribes": ["SPDXRef-root"],
		 "packages": [
		   {"SPDXID": "SPDXRef-root", "name": "image", "versionInfo": "1"},
		   {"SPDXID": "SPDXRef-p", "name": "rom", "versionInfo": "1"` + fields + `}]}`
	}
	summary := `, "summary": "Intel Boot Agent"`
	description := `, "description": "A boot agent.\n\nIt loads an operating system over the network."`
	for _, tc := range []struct{ name, fields, want string }{
		{"summary first", summary + description, "Intel Boot Agent"},
		{"description first", description + summary, "Intel Boot Agent"},
		{"description alone", description, "A boot agent. It loads an operating system over the network."},
		{"the word for nothing", `, "summary": "NOASSERTION"` + description,
			"A boot agent. It loads an operating system over the network."},
		{"a description saying nothing", `, "description": "NOASSERTION"`, ""},
		{"nothing", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := describedAs(t, document(tc.fields))["rom"]; got != tc.want {
				t.Errorf("the package is described as %q, want %q", got, tc.want)
			}
		})
	}
}

// The third format's elements carry the same two properties, and are read by
// the same rule.
func TestAThirdFormatPackagesSummaryBeatsItsDescription(t *testing.T) {
	document := func(fields string) string {
		return `{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [
    {"@id": "_:creationInfo", "type": "CreationInfo", "specVersion": "3.0.1",
     "created": "2026-08-14T09:12:33Z"},
    {"spdxId": "https://example.invalid/product-1.0", "type": "SpdxDocument",
     "creationInfo": "_:creationInfo", "rootElement": ["urn:root"]},
    {"spdxId": "urn:root", "type": "software_Package", "creationInfo": "_:creationInfo",
     "name": "product", "software_packageVersion": "1.0"},
    {"spdxId": "urn:a", "type": "software_Package", "creationInfo": "_:creationInfo",
     "name": "rom", "software_packageVersion": "1"` + fields + `},
    {"spdxId": "urn:rel", "type": "Relationship", "creationInfo": "_:creationInfo",
     "from": "urn:root", "relationshipType": "dependsOn", "to": ["urn:a"]}
  ]}`
	}
	for _, tc := range []struct{ name, fields, want string }{
		{"both", `, "description": "A boot agent, at length.", "summary": "Intel Boot Agent"`, "Intel Boot Agent"},
		{"description alone", `, "description": "A boot agent."`, "A boot agent."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := describedAs(t, document(tc.fields))["rom"]; got != tc.want {
				t.Errorf("the package is described as %q, want %q", got, tc.want)
			}
		})
	}
}

// Two entries for one component are one component, and the second fills in a
// description the first left out.
func TestADescriptionTheFirstEntryLacksIsTakenFromTheSecond(t *testing.T) {
	said := describedAs(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"component": {"bom-ref": "root", "name": "product", "version": "1.0"}},
  "components": [
    {"bom-ref": "a", "name": "rom", "version": "1", "purl": "pkg:generic/rom@1"},
    {"bom-ref": "b", "name": "rom", "version": "1", "purl": "pkg:generic/rom@1", "description": "Boot agent"},
    {"bom-ref": "c", "name": "rom", "version": "1", "purl": "pkg:generic/rom@1", "description": "Something else"}
  ],
  "dependencies": [{"ref": "root", "dependsOn": ["a"]}]
}`)
	if got := said["rom"]; got != "Boot agent" {
		t.Errorf("the component is described as %q, want the first statement of one", got)
	}
}
