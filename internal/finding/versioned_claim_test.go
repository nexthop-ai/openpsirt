// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

func TestAStatementAboutOneVersionDoesNotSuppressAnother(t *testing.T) {
	// A publisher naming no package states the version as the branch its
	// product sits in. The statement that 4.2 is not affected says nothing
	// about 5.0, and a build that moves to 5.0 while sending the same file
	// keeps its finding open.
	//
	// On every engine, because the version travels through the stored row:
	// what is matched is what was read back.
	each(t, func(t *testing.T, f *fixture) {
		statement := sbom.Suppression{
			Vulnerability: "CVE-2026-7", Status: sbom.NotAffected,
			Justification: "vulnerable_code_not_present",
			Targets:       []sbom.Target{{Name: "acme-fw", Version: "4.2"}},
			Origin:        sbom.FromStatement,
		}

		for _, step := range []struct {
			shipping   graph.Described
			suppressed bool
		}{
			{graph.Described{Name: "acme-fw", Version: "4.2"}, true},
			{graph.Described{Name: "acme-fw", Version: "5.0"}, false},
		} {
			f.shipped(t, graph.Snapshot{Root: root, Components: []graph.Described{step.shipping},
				Dependencies: []graph.Dependency{{Parent: root, Child: step.shipping}}})
			if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
				[]sbom.Suppression{statement}, everyOrigin); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
				[]finding.Reported{found("CVE-2026-7", step.shipping)}); err != nil {
				t.Fatal(err)
			}
			rows := f.open(t)
			if len(rows) != 1 {
				t.Fatalf("at %s, %d findings are open, want the one", step.shipping.Version, len(rows))
			}
			if got := rows[0].SuppressedBy != nil; got != step.suppressed {
				t.Errorf("at %s the statement about 4.2 suppresses the finding: %v, want %v",
					step.shipping.Version, got, step.suppressed)
			}
		}

		// The version is what the carried patches read shows beside the name,
		// and the one statement sent twice is one claim.
		carried, _, err := f.store.CarriedPatches(t.Context(), f.holding(t, access.PublicRead),
			f.target, "", 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(carried) != 1 || carried[0].Subject != "acme-fw" || carried[0].Version != "4.2" {
			t.Errorf("the carried patches read %+v, want acme-fw at 4.2 once", carried)
		}
	})
}

func TestAVersionInsideAPackageIdentifierIsNotStoredAgain(t *testing.T) {
	// The identifier already carries it, and through the identifier it is
	// already part of the claim's identity. Stored again, every claim about a
	// versioned identifier held before the version was kept would close and
	// reopen on the next scan.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{{
				Vulnerability: "CVE-2026-8", Status: sbom.NotAffected,
				Justification: "vulnerable_code_not_present",
				Targets:       []sbom.Target{{Purl: libnl.Purl, Name: libnl.Name, Version: libnl.Version}},
				Origin:        sbom.FromStatement,
			}}, everyOrigin); err != nil {
			t.Fatal(err)
		}
		carried, _, err := f.store.CarriedPatches(t.Context(), f.holding(t, access.PublicRead),
			f.target, "", 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(carried) != 1 {
			t.Fatalf("%d claims are stored, want the one", len(carried))
		}
		if carried[0].Version != "" {
			t.Errorf("a version inside the identifier is stored again as %q", carried[0].Version)
		}
	})
}
