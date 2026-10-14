// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/bound/boundtest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// listOf is n JSON values made by one, separated by commas.
func listOf(n int, one func(i int) string) string {
	parts := make([]string, n)
	for i := range n {
		parts[i] = one(i)
	}
	return strings.Join(parts, ",")
}

// raised is a set of limits where only the one under test can be reached.
func raised(set func(*sbom.Limits)) sbom.Limits {
	lim := sbom.Limits{
		MaxBytes: 1 << 24, MaxComponents: 1 << 16, MaxFiles: 1 << 16,
		MaxEdges: 1 << 16, MaxStatements: 1 << 16, MaxDepth: 64, MaxDocuments: 8,
	}
	set(&lim)
	return lim
}

func inventory(lim sbom.Limits) func(string) error {
	return func(body string) error {
		_, err := sbom.Read(strings.NewReader(body), lim)
		return err
	}
}

func suppressions(lim sbom.Limits) func(string) error {
	return func(body string) error {
		_, err := sbom.ReadSuppressions(strings.NewReader(body), lim)
		return err
	}
}

// spdx3Imports is a graph whose document element comes last and imports
// imports others, so the imports are the last thing charged.
func spdx3Imports(imports int) string {
	return `{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [
	  {"@id": "_:creationInfo", "type": "CreationInfo", "specVersion": "3.0.1",
	   "created": "2026-08-14T09:12:33Z"},
	  {"spdxId": "urn:root", "type": "software_Package", "creationInfo": "_:creationInfo",
	   "name": "product", "software_packageVersion": "1.0"},
	  {"spdxId": "urn:a", "type": "software_Package", "creationInfo": "_:creationInfo",
	   "name": "libc", "software_packageVersion": "2.41"},
	  {"spdxId": "urn:rel", "type": "Relationship", "creationInfo": "_:creationInfo",
	   "from": "urn:root", "relationshipType": "dependsOn", "to": ["urn:a"]},
	  {"spdxId": "urn:doc", "type": "SpdxDocument", "creationInfo": "_:creationInfo",
	   "rootElement": ["urn:root"], "import": [` + listOf(imports, func(i int) string {
		return fmt.Sprintf(`{"type": "ExternalMap", "externalSpdxId": "urn:other%d"}`, i)
	}) + `]}]}`
}

// Every charge against a bound is reached by an input whose last charge is
// that one, so the refusal at limit+1 is the arm the case names and no other.
// Each document charges exactly n against the bound under test.
func TestEveryChargeIsRefusedOnePastItsLimit(t *testing.T) {
	const limit = 7
	cases := []struct {
		name  string
		words string
		lim   func(*sbom.Limits)
		read  func(sbom.Limits) func(string) error
		body  func(n int) string
	}{
		{
			// The description of the root and one dependency are charged
			// first, then one more dependency each.
			name: "an SPDX 2 relationship", words: "dependency limit",
			lim: func(l *sbom.Limits) { l.MaxEdges = limit }, read: inventory,
			body: func(n int) string {
				more := listOf(n-2, func(int) string {
					return `{"spdxElementId": "SPDXRef-root", "relatedSpdxElement": "SPDXRef-a",
					  "relationshipType": "DEPENDS_ON"}`
				})
				return strings.Replace(minimalSPDX, `"relationshipType": "DEPENDS_ON"}`,
					`"relationshipType": "DEPENDS_ON"},`+more, 1)
			},
		},
		{
			name: "a CycloneDX component nested in another", words: "dependency limit",
			lim: func(l *sbom.Limits) { l.MaxEdges = limit }, read: inventory,
			body: func(n int) string {
				return `{"bomFormat": "CycloneDX", "specVersion": "1.6",
				  "metadata": {"component": {"bom-ref": "root", "name": "p", "version": "1"}},
				  "components": [{"bom-ref": "a", "name": "a", "version": "1", "components": [` +
					listOf(n, func(i int) string {
						return fmt.Sprintf(`{"bom-ref": "m%d", "name": "m%d", "version": "1"}`, i, i)
					}) + `]}]}`
			},
		},
		{
			// The creation record, two packages, the document and its root
			// element are charged, the relationship handing its charge to
			// the edge bound, then one import each.
			name: "an SPDX 3 import", words: "component limit",
			lim: func(l *sbom.Limits) { l.MaxComponents = limit }, read: inventory,
			body: func(n int) string { return spdx3Imports(n - 5) },
		},
		{
			name: "an SPDX 3 ancestor", words: "claim limit",
			lim: func(l *sbom.Limits) { l.MaxStatements = limit }, read: inventory,
			body: func(n int) string {
				return strings.Replace(minimalSPDX3, `"to": ["urn:a"]}`, `"to": ["urn:a"]},
				  {"spdxId": "urn:anc", "type": "Relationship", "creationInfo": "_:creationInfo",
				   "from": "urn:a", "relationshipType": "descendantOf", "to": [`+
					listOf(n, func(i int) string { return fmt.Sprintf(`"urn:up%d"`, i) })+`]}`, 1)
			},
		},
		{
			// The product is charged first, then one alias each.
			name: "an OpenVEX alias", words: "product limit",
			lim: func(l *sbom.Limits) { l.MaxComponents = limit }, read: suppressions,
			body: func(n int) string {
				return `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{
				  "products": [{"@id": "pkg:deb/debian/libc6@2.41"}],
				  "status": "not_affected", "justification": "component_not_present",
				  "vulnerability": {"name": "CVE-2026-1", "aliases": [` +
					listOf(n-1, func(i int) string { return fmt.Sprintf(`"GHSA-%d"`, i) }) + `]}}]}`
			},
		},
		{
			name: "a CSAF product status", words: "product limit",
			lim: func(l *sbom.Limits) { l.MaxComponents = limit }, read: suppressions,
			body: func(n int) string {
				tree, _ := csafProducts(1, "")
				return csafDocument("csaf_vex", tree, `[{"cve": "CVE-2026-1", "product_status":
				  {"known_not_affected": ["P0", `+
					listOf(n-1, func(i int) string { return fmt.Sprintf(`"X%d"`, i) })+`]}}]`)
			},
		},
		{
			name: "a CSAF flag's products", words: "product limit",
			lim: func(l *sbom.Limits) { l.MaxComponents = limit }, read: suppressions,
			body: func(n int) string {
				tree, _ := csafProducts(1, "")
				return csafDocument("csaf_vex", tree, `[{"cve": "CVE-2026-1",
				  "product_status": {"known_not_affected": ["P0"]},
				  "flags": [{"label": "component_not_present", "product_ids": [`+
					listOf(n-1, func(i int) string { return fmt.Sprintf(`"X%d"`, i) })+`]}]}]`)
			},
		},
		{
			name: "a CSAF group's products", words: "product limit",
			lim: func(l *sbom.Limits) { l.MaxComponents = limit }, read: suppressions,
			body: func(n int) string {
				tree, _ := csafProducts(1, `[{"group_id": "G", "product_ids": [`+
					listOf(n-1, func(i int) string { return fmt.Sprintf(`"X%d"`, i) })+`]}]`)
				return csafDocument("csaf_vex", tree,
					`[{"cve": "CVE-2026-1", "product_status": {"known_not_affected": ["P0"]}}]`)
			},
		},
	}
	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			read := each.read(raised(each.lim))
			boundtest.Edges(t, limit, func(n int) error { return read(each.body(n)) }, func(err error) bool { return strings.Contains(err.Error(), each.words) })
		})
	}
}

// A depth bound is pinned by the limit rather than the input. The document's
// deepest value sits inside the object the arm under test enters, one level
// below it, so the arm is what puts that value past a limit one less than its
// depth: without the arm, the value sits a level higher and is read. Two less,
// the object is the first value past the limit, and the arm refuses it.
func TestEveryNestingArmIsRefusedOnePastItsLimit(t *testing.T) {
	cases := []struct {
		name string
		read func(sbom.Limits) func(string) error
		body string
	}{
		{
			// The document, the statements, a statement, the vulnerability
			// written as an object, and a list inside it.
			name: "a value written as a string or an object", read: suppressions,
			body: `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{
			  "vulnerability": {"name": "CVE-2026-1", "x": [1]},
			  "products": ["pkg:deb/debian/libc6@2.41"], "status": "not_affected",
			  "justification": "component_not_present"}]}`,
		},
		{
			// The document, the graph, an element, its root elements written
			// as an object, and a list inside it.
			name: "a list written as an object", read: inventory,
			body: strings.Replace(minimalSPDX3, `"@graph": [`, `"@graph": [
				{"spdxId": "urn:sbom", "type": "software_Sbom", "rootElement": {"x": ["urn:root"]}},`, 1),
		},
	}
	const depth = 5
	for _, each := range cases {
		t.Run(each.name, func(t *testing.T) {
			at := each.read(raised(func(l *sbom.Limits) { l.MaxDepth = depth }))
			if err := at(each.body); err != nil {
				t.Fatalf("at the limit (%d): %v", depth, err)
			}
			under := each.read(raised(func(l *sbom.Limits) { l.MaxDepth = depth - 1 }))
			if err := under(each.body); err == nil || !strings.Contains(err.Error(), "nests deeper") {
				t.Fatalf("under the limit (%d): want a refusal for depth, got %v", depth-1, err)
			}
			further := each.read(raised(func(l *sbom.Limits) { l.MaxDepth = depth - 2 }))
			if err := further(each.body); err == nil || !strings.Contains(err.Error(), "nests deeper") {
				t.Fatalf("two under the limit (%d): want a refusal for depth, got %v", depth-2, err)
			}
		})
	}
}
