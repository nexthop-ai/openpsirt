// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// licenses is each component's license, by name.
func licenses(doc *sbom.Document) map[string]string {
	said := map[string]string{}
	for _, c := range doc.Components {
		said[c.Name] = c.License
	}
	return said
}

func TestEachFormatReadsTheLicenseAProducerWrote(t *testing.T) {
	for _, c := range []struct {
		fixture string
		want    map[string]string
	}{
		{"openpsirt-image.cdx.json", map[string]string{
			"alpine-keys": "MIT", "apk-tools": "GPL-2.0-only"}},
		// Declared NOASSERTION and concluded from the source: the conclusion
		// is what is known.
		{"rust-app.spdx.json", map[string]string{
			"hyper": "MIT", "pretty_env_logger": "MIT OR Apache-2.0"}},
		{"rust-app.spdx3.json", map[string]string{
			"hyper": "MIT", "pretty_env_logger": "(MIT OR Apache-2.0)"}},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			doc, err := sbom.Read(fixture(t, c.fixture), sbom.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			got := licenses(doc)
			for name, want := range c.want {
				if got[name] != want {
					t.Errorf("%s: license %q, want %q", name, got[name], want)
				}
			}
		})
	}
}

func TestSeveralCycloneDXLicensesAreOneConjunction(t *testing.T) {
	doc := read(t, `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
		{"name":"several","version":"1","licenses":[
			{"license":{"name":"GPL-2+"}},{"license":{"id":"MIT"}},
			{"expression":"BSD-3-Clause OR Apache-2.0"},{"license":{"id":"MIT"}}]},
		{"name":"groups","version":"1","licenses":[
			{"expression":"(MIT) OR (Zlib)"},{"expression":"(ISC OR 0BSD)"}]},
		{"name":"both","version":"1","licenses":[{"license":{"name":"Expat","id":"MIT"}}]},
		{"name":"concluded","version":"1","licenses":[
			{"license":{"id":"Apache-2.0","acknowledgement":"concluded"}}]},
		{"name":"declared","version":"1","licenses":[
			{"license":{"id":"Apache-2.0","acknowledgement":"concluded"}},
			{"license":{"id":"MIT","acknowledgement":"declared"}}]},
		{"name":"named","version":"1","licenses":[
			{"license":{"name":"Apache License 2.0"}},{"license":{"id":"MIT"}}]},
		{"name":"none","version":"1"}]}`)
	got := licenses(doc)
	for name, want := range map[string]string{
		"several":   "GPL-2+ AND MIT AND (BSD-3-Clause OR Apache-2.0)",
		"groups":    "((MIT) OR (Zlib)) AND (ISC OR 0BSD)",
		"both":      "MIT",
		"concluded": "Apache-2.0",
		"declared":  "MIT",
		"named":     "Apache License 2.0 AND MIT",
		"none":      "",
	} {
		if got[name] != want {
			t.Errorf("%s: license %q, want %q", name, got[name], want)
		}
	}
}

func TestAnSPDX3LicenseNamedOnlyByTheListIsRead(t *testing.T) {
	doc := read(t, `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[
		{"type":"software_Package","spdxId":"p1","name":"listed","software_packageVersion":"1"},
		{"type":"software_Package","spdxId":"p2","name":"custom","software_packageVersion":"1"},
		{"type":"expandedlicensing_CustomLicense","spdxId":"l2","name":"LicenseRef-Vendor"},
		{"type":"Relationship","spdxId":"r1","from":"p1","relationshipType":"hasDeclaredLicense",
		 "to":["https://spdx.org/licenses/BSD-2-Clause"]},
		{"type":"Relationship","spdxId":"r2","from":"p2","relationshipType":"hasDeclaredLicense","to":["l2"]}]}`)
	got := licenses(doc)
	if got["listed"] != "BSD-2-Clause" || got["custom"] != "LicenseRef-Vendor" {
		t.Errorf("licenses %v", got)
	}
}

func TestADeclaredLicenseStandsOverAConcludedOne(t *testing.T) {
	// Every fixture package either declares nothing or declares what it
	// concludes, so these are the only inputs where the order shows.
	spdx2 := read(t, `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","packages":[
		{"SPDXID":"SPDXRef-a","name":"both","versionInfo":"1",
		 "licenseConcluded":"Apache-2.0","licenseDeclared":"MIT"}]}`)
	spdx3 := read(t, `{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[
		{"type":"software_Package","spdxId":"p1","name":"both","software_packageVersion":"1"},
		{"type":"simplelicensing_LicenseExpression","spdxId":"l1","simplelicensing_licenseExpression":"Apache-2.0"},
		{"type":"simplelicensing_LicenseExpression","spdxId":"l2","simplelicensing_licenseExpression":"MIT"},
		{"type":"Relationship","spdxId":"r1","from":"p1","relationshipType":"hasConcludedLicense","to":["l1"]},
		{"type":"Relationship","spdxId":"r2","from":"p1","relationshipType":"hasDeclaredLicense","to":["l2"]}]}`)
	for format, doc := range map[string]*sbom.Document{"SPDX 2": spdx2, "SPDX 3": spdx3} {
		if got := licenses(doc)["both"]; got != "MIT" {
			t.Errorf("%s: license %q, want the declared MIT", format, got)
		}
	}
}
