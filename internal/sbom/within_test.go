// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// withinOf is the product a target ships inside, as the identifier and the
// version it was stated at, or empty where none was named.
func withinOf(at sbom.Target) (string, string) {
	if at.Within == nil {
		return "", ""
	}
	return at.Within.Purl, at.Within.VersionNamed()
}

// A supplier's statement about a component inside its product is kept with
// the product, because the product is what places it in a build. The three
// shapes a supplier states its own product in each read the way they were
// written: the component inside the product at a version, the product alone,
// and the product with no version.
func TestAStatementAboutAComponentInsideAProductKeepsTheProduct(t *testing.T) {
	got, err := sbom.ReadSuppressions(fixture(t, "supplier-product-inside.openvex.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d claims, want 3", len(got))
	}
	byIssue := map[string]sbom.Target{}
	for _, one := range got {
		if len(one.Targets) != 1 {
			t.Fatalf("the claim about %s points at %+v", one.Vulnerability, one.Targets)
		}
		byIssue[one.Vulnerability] = one.Targets[0]
	}

	inside := byIssue["CVE-2022-37434"]
	if inside.ComponentNamed() != "zlib" {
		t.Errorf("the claim inside the product is about %q", inside.ComponentNamed())
	}
	if purl, version := withinOf(inside); purl != "pkg:generic/acme-y@4.2" || version != "4.2" {
		t.Errorf("the claim inside the product ships inside %q at %q", purl, version)
	}

	alone := byIssue["CVE-2023-45853"]
	if alone.Within != nil {
		t.Errorf("the product named alone ships inside %+v", *alone.Within)
	}
	if alone.ComponentNamed() != "acme-y" || alone.VersionNamed() != "4.2" {
		t.Errorf("the product named alone is %q at %q", alone.ComponentNamed(), alone.VersionNamed())
	}

	unversioned := byIssue["CVE-2018-25032"]
	if purl, version := withinOf(unversioned); purl != "pkg:generic/acme-y" || version != "" {
		t.Errorf("the product named with no version ships inside %q at %q", purl, version)
	}
}

// The CSAF profile composes a component into a product by a relationship, and
// the product's version is the branch it sits under. The composite resolves to
// the component, as it always has, and the product it relates to is kept.
func TestACompositeKeepsTheProductItRelatesTo(t *testing.T) {
	got, err := sbom.ReadSuppressions(fixture(t, "supplier-product-inside.csaf.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1 || len(got[0].Targets) != 1 {
		t.Fatalf("read %+v", got)
	}
	one := got[0]
	if one.Status != sbom.NotAffected || one.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("the claim says %q, %q", one.Status, one.Justification)
	}
	at := one.Targets[0]
	if at.Purl != "pkg:generic/zlib@1.2.11" {
		t.Errorf("the composite resolved to %q", at.Purl)
	}
	if purl, version := withinOf(at); purl != "pkg:generic/acme-y@4.2" || version != "4.2" {
		t.Errorf("the composite ships inside %q at %q", purl, version)
	}
}

// A product that is only the name of a platform, with no identifier and no
// version, is still what the package ships inside, and is kept as named.
func TestAPlatformNamedByACPEIsKeptByName(t *testing.T) {
	got := readAdvisory(t, "advisory-platform-packages.csaf.json")
	var seen int
	for _, one := range got.Claims {
		for _, at := range one.Targets {
			seen++
			if at.Within == nil {
				t.Errorf("%s inside a platform kept no platform", at.Purl)
				continue
			}
			if at.Within.Name != "Example Platform BaseOS (v. 9)" || at.Within.Purl != "" {
				t.Errorf("%s ships inside %+v", at.Purl, *at.Within)
			}
		}
	}
	if seen == 0 {
		t.Fatal("the advisory pointed at nothing, so this checked nothing")
	}
}
