package sbom_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// A conforming CSAF-VEX document, in the shape a distribution publishes: the
// products are defined in a tree and the claims point at them by identifier,
// which is the whole difference from OpenVEX.
const csafVex = `{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "publisher": {"category": "vendor", "name": "Example Distribution",
                  "namespace": "https://example.test"},
    "title": "Statements about libnl",
    "tracking": {"id": "EX-2026-1", "version": "1", "status": "final",
                 "current_release_date": "2026-09-01T00:00:00Z",
                 "initial_release_date": "2026-09-01T00:00:00Z",
                 "revision_history": [{"number": "1", "date": "2026-09-01T00:00:00Z",
                                       "summary": "First"}]}
  },
  "product_tree": {
    "branches": [{
      "category": "vendor", "name": "Example",
      "branches": [{
        "category": "product_name", "name": "libnl",
        "product": {
          "product_id": "LIBNL-370",
          "name": "libnl-3-200 3.7.0",
          "product_identification_helper": {"purl": "pkg:deb/debian/libnl-3-200@3.7.0"}
        }
      }]
    }],
    "full_product_names": [{
      "product_id": "ZLIB-113",
      "name": "zlib1g 1.1.3",
      "product_identification_helper": {"purl": "pkg:deb/debian/zlib1g@1.1.3"}
    }]
  },
  "vulnerabilities": [{
    "cve": "CVE-2026-1",
    "ids": [{"system_name": "Example", "text": "EX-1"}],
    "product_status": {
      "known_not_affected": ["LIBNL-370"],
      "known_affected": ["ZLIB-113"]
    },
    "flags": [{"label": "vulnerable_code_not_present", "product_ids": ["LIBNL-370"]}],
    "threats": [{"category": "impact", "details": "The parser is not built in.",
                 "product_ids": ["LIBNL-370"]}],
    "remediations": [{"category": "workaround", "details": "Disable the listener.",
                      "product_ids": ["ZLIB-113"]}]
  }]
}`

func TestACSAFVexDocumentReadsAsTheSameClaims(t *testing.T) {
	// a supplier's VEX as evidence named CSAF-VEX from the start and it
	// was refused with a sentence. The two formats say the same thing in
	// different shapes — one puts the status on a statement, the other in
	// which list a product identifier appears in — and both have to become
	// the same claim, because what a build is telling us does not depend
	// on which file it wrote it in.
	claims, err := sbom.ReadSuppressions(strings.NewReader(csafVex), sbom.Limits{})
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("%d claims, want one per status: %+v", len(claims), claims)
	}
	var notAffected, affected *sbom.Suppression
	for i := range claims {
		switch claims[i].Status {
		case sbom.NotAffected:
			notAffected = &claims[i]
		case sbom.Affected:
			affected = &claims[i]
		}
	}
	if notAffected == nil || affected == nil {
		t.Fatalf("the two statuses did not both come back: %+v", claims)
	}

	if notAffected.Vulnerability != "CVE-2026-1" {
		t.Errorf("the claim is about %q", notAffected.Vulnerability)
	}
	if len(notAffected.Aliases) != 1 || notAffected.Aliases[0] != "EX-1" {
		t.Errorf("the other names it goes by are %v", notAffected.Aliases)
	}
	// The product identifier resolved through the tree to something that can
	// be matched against a component — which is the work this reader exists to
	// do, since the identifier itself is somebody else's key.
	if len(notAffected.Targets) != 1 || notAffected.Targets[0].Name != "libnl-3-200" {
		t.Errorf("what it points at is %+v", notAffected.Targets)
	}
	if notAffected.Justification != "vulnerable_code_not_present" {
		t.Errorf("the justification is %q", notAffected.Justification)
	}
	// The prose is kept apart by status: an impact statement argues that
	// something is not affected and an action statement says what to do about
	// something that is, and reading either into both would attach an argument
	// to a claim it was not made about.
	if notAffected.Statement != "The parser is not built in." {
		t.Errorf("the not-affected claim says %q", notAffected.Statement)
	}
	if affected.Statement != "Disable the listener." {
		t.Errorf("the affected claim says %q", affected.Statement)
	}
	// A build saying it is affected suppresses nothing; saying it is not does.
	if !notAffected.Status.Suppresses() || affected.Status.Suppresses() {
		t.Errorf("suppression is the wrong way round: %+v %+v", notAffected, affected)
	}
	// Read from a document rather than attached to a component, which is what
	// tells a statement from a carried patch.
	if notAffected.Origin != sbom.FromStatement {
		t.Errorf("the claim came from %q", notAffected.Origin)
	}
}

func TestACSAFAdvisoryIsNotReadAsClaimsAboutABuild(t *testing.T) {
	// An advisory is a different document about somebody's own flaws. Reading
	// one as though it were a set of claims about what a build ships would
	// take their advisory as our build's argument, and every product it names
	// as a suppression.
	advisory := strings.ReplaceAll(csafVex, `"csaf_vex"`, `"csaf_security_advisory"`)
	if _, err := sbom.ReadSuppressions(strings.NewReader(advisory), sbom.Limits{}); err == nil {
		t.Error("a CSAF advisory was read as claims about a build")
	}
}

func TestACSAFClaimPointingAtNothingIsRefused(t *testing.T) {
	// A claim we cannot place is a build's judgment going missing quietly,
	// which is the failure this whole arrangement exists to remove.
	orphaned := strings.ReplaceAll(csafVex, `"known_not_affected": ["LIBNL-370"]`,
		`"known_not_affected": ["NOT-IN-THE-TREE"]`)
	orphaned = strings.ReplaceAll(orphaned, `"known_affected": ["ZLIB-113"]`,
		`"known_affected": ["ALSO-NOT-THERE"]`)
	if _, err := sbom.ReadSuppressions(strings.NewReader(orphaned), sbom.Limits{}); err == nil {
		t.Error("a claim pointing at nothing the document defines was accepted")
	}
}

func TestATreeAfterTheClaimsStillResolves(t *testing.T) {
	// Nothing in the format promises an order, so the identifiers are
	// collected as they are read and resolved once the document is closed.
	var tree, vulns string
	if i := strings.Index(csafVex, `"product_tree"`); i > 0 {
		j := strings.Index(csafVex, `"vulnerabilities"`)
		tree = csafVex[i : j-4]
		vulns = csafVex[j : len(csafVex)-2]
	}
	reordered := csafVex[:strings.Index(csafVex, `"product_tree"`)] + vulns + ",\n  " + tree + "\n}"
	claims, err := sbom.ReadSuppressions(strings.NewReader(reordered), sbom.Limits{})
	if err != nil {
		t.Fatalf("reading a document whose tree comes last: %v", err)
	}
	if len(claims) != 2 {
		t.Errorf("%d claims when the tree came last, want the two", len(claims))
	}
}
