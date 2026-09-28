// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// held is how much heap reading this document leaves behind, in bytes per
// unit of whatever the document is mostly made of.
func held(t *testing.T, body string, units int) float64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	doc, err := sbom.Read(strings.NewReader(body), sbom.Limits{
		MaxEdges: units * 2, MaxComponents: units * 2, MaxFiles: units * 2,
	}.OrDefault())
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(doc)
	return float64(after.HeapAlloc-before.HeapAlloc) / float64(units)
}

func TestTheCeilingsAreSetFromWhatReadingActuallyCosts(t *testing.T) {
	// The bounds exist so that a document nobody could have meant cannot take
	// the process down. Measured, an edge costs about half a kilobyte of heap
	// while it is being read, so two million edges is about a gigabyte from a
	// seventy-megabyte file, in the background reader that runs after the
	// upload was answered 202.
	//
	// This is a wide bound rather than the measured number: heap accounting
	// varies between runs and between versions of Go, and what it is for is
	// catching a change that makes an edge an order of magnitude dearer, which
	// would quietly make the ceiling permit many times its budget.
	const perEdge = 2048
	const perComponent = 4096
	const perFile = 1024

	t.Run("an edge", func(t *testing.T) {
		const edges = 200_000
		var b strings.Builder
		b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":` +
			`{"bom-ref":"root","type":"application","name":"root","version":"1"}},"components":[`)
		for i := 0; i < 2000; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"bom-ref":"c%d","type":"library","name":"c%d","version":"1"}`, i, i)
		}
		b.WriteString(`],"dependencies":[`)
		for i := 0; i < edges; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"ref":"c%d","dependsOn":["c%d"]}`, i%2000, (i+1)%2000)
		}
		b.WriteString(`]}`)

		cost := held(t, b.String(), edges)
		t.Logf("%.0f bytes of heap per edge; the ceiling of %d permits %.0f MB",
			cost, sbom.DefaultLimits().MaxEdges,
			cost*float64(sbom.DefaultLimits().MaxEdges)/(1<<20))
		if cost > perEdge {
			t.Errorf("an edge costs %.0f bytes of heap, over the %d this ceiling was set "+
				"against — the ceiling now permits %.0f MB", cost, perEdge,
				cost*float64(sbom.DefaultLimits().MaxEdges)/(1<<20))
		}
	})

	t.Run("a cataloged path", func(t *testing.T) {
		// Bounded apart from components because a real document holds forty-
		// five to fifty-six of them per package, and because a file is only
		// the identifier — kept so an edge naming it is dropped knowingly —
		// where a component is a described thing. The higher ceiling is only
		// affordable while that stays true.
		const files = 50_000
		var b strings.Builder
		b.WriteString(`{"spdxVersion":"SPDX-2.3","documentNamespace":"https://example.invalid/f","files":[`)
		for i := 0; i < files; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"SPDXID":"SPDXRef-File-path-%d","fileName":"usr/share/doc/package/file-%d"}`, i, i)
		}
		b.WriteString(`]}`)

		cost := held(t, b.String(), files)
		t.Logf("%.0f bytes of heap per cataloged path; the ceiling of %d permits %.0f MB",
			cost, sbom.DefaultLimits().MaxFiles,
			cost*float64(sbom.DefaultLimits().MaxFiles)/(1<<20))
		if cost > perFile {
			t.Errorf("a cataloged path costs %.0f bytes of heap, over the %d this ceiling was "+
				"set against — the ceiling now permits %.0f MB", cost, perFile,
				cost*float64(sbom.DefaultLimits().MaxFiles)/(1<<20))
		}
	})

	t.Run("a component", func(t *testing.T) {
		const components = 50_000
		var b strings.Builder
		b.WriteString(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":` +
			`{"bom-ref":"root","type":"application","name":"root","version":"1"}},"components":[`)
		for i := 0; i < components; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"bom-ref":"c%d","type":"library","name":"package-%d",`+
				`"version":"1.2.3","purl":"pkg:deb/debian/package-%d@1.2.3"}`, i, i, i)
		}
		b.WriteString(`]}`)

		cost := held(t, b.String(), components)
		t.Logf("%.0f bytes of heap per component; the ceiling of %d permits %.0f MB",
			cost, sbom.DefaultLimits().MaxComponents,
			cost*float64(sbom.DefaultLimits().MaxComponents)/(1<<20))
		if cost > perComponent {
			t.Errorf("a component costs %.0f bytes of heap, over the %d this ceiling was "+
				"set against — the ceiling now permits %.0f MB", cost, perComponent,
				cost*float64(sbom.DefaultLimits().MaxComponents)/(1<<20))
		}
	})
}

func TestEveryLicenseEntryAComponentStatesIsCharged(t *testing.T) {
	// Each entry is kept, so one component stating as many as the byte bound
	// allows is held whole unless each is charged.
	licensed := func(count int) string {
		var b strings.Builder
		for i := range count {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"expression": "L%d"}`, i)
		}
		return strings.Replace(minimal, `"purl": "pkg:deb/debian/libc6@2.41"`,
			`"purl": "pkg:deb/debian/libc6@2.41", "licenses": [`+b.String()+`]`, 1)
	}
	if _, err := sbom.Read(strings.NewReader(licensed(5)), sbom.Limits{MaxStatements: 5}); err != nil {
		t.Fatalf("five licenses at a bound of five: %v", err)
	}
	_, err := sbom.Read(strings.NewReader(licensed(6)), sbom.Limits{MaxStatements: 5})
	if err == nil {
		t.Fatal("six licenses were held under a bound of five")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal does not name a limit: %v", err)
	}
}

func TestARelationshipWithNoEndKeepsItsCharge(t *testing.T) {
	// A relationship's ends are charged against the edge bound, and its
	// component charge is handed back for that reason. One stating no end is
	// charged nothing there and is still kept.
	var b strings.Builder
	b.WriteString(`{"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": [`)
	for i := range 6 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"spdxId": "urn:r%d", "type": "Relationship", "from": "urn:x",
		  "relationshipType": "describes"}`, i)
	}
	b.WriteString(`]}`)
	_, err := sbom.Read(strings.NewReader(b.String()), sbom.Limits{MaxComponents: 5})
	if err == nil {
		t.Fatal("six relationships with no end were held under a bound of five")
	}
	if !strings.Contains(err.Error(), "component limit") {
		t.Errorf("the refusal does not name the limit it hit: %v", err)
	}
}
