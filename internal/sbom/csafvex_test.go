// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
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
	// A supplier's VEX arrives as CSAF-VEX as well as OpenVEX. The two
	// formats say the same thing in
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

// A CSAF product that names a source tree and carries no package identifier,
// which is what a distribution's automatically extracted claims look like.
const csafNamedOnly = `{
  "document": {"category": "csaf_vex", "csaf_version": "2.0",
    "publisher": {"category": "vendor", "name": "Example Distribution",
                  "namespace": "https://example.test"},
    "title": "Statements about thrift",
    "tracking": {"id": "EX-2026-2", "version": "1", "status": "final",
                 "current_release_date": "2026-09-01T00:00:00Z",
                 "initial_release_date": "2026-09-01T00:00:00Z",
                 "revision_history": [{"number": "1", "date": "2026-09-01T00:00:00Z",
                                       "summary": "First"}]}},
  "product_tree": {"full_product_names": [{"product_id": "THRIFT", "name": "thrift"}]},
  "vulnerabilities": [{
    "cve": "CVE-2017-1000487",
    "product_status": {"known_not_affected": ["THRIFT"]}
  }]
}`

func TestAClaimNamingNoPackageIdentifierStillCoversWhatItNames(t *testing.T) {
	// The producer's automatically extracted claims name source trees rather
	// than packages, so a product with no purl helper is the ordinary case and
	// not the exception. Read as covering nothing, every one of these is
	// accepted, stored, reported as recorded and silently without effect: the
	// finding the build has already answered stays open as noise.
	got, err := sbom.ReadSuppressions(strings.NewReader(csafNamedOnly), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("read %d claims, want 1", len(got))
	}
	if len(got[0].Targets) != 1 || got[0].Targets[0].Purl != "" {
		t.Fatalf("what it points at is %+v", got[0].Targets)
	}

	named := graph.Described{Purl: "pkg:deb/debian/libthrift@0.14.1", Name: "thrift", Version: "0.14.1"}
	forked := graph.Described{
		Purl: "pkg:deb/sonic/thriftshim@1.0", Name: "thriftshim", Version: "1.0", UpstreamName: "thrift",
	}
	elsewhere := graph.Described{
		Purl: "pkg:deb/debian/thrift-compiler@0.14.1", Name: "thrift-compiler", Version: "0.14.1",
	}
	if !got[0].Covers(named) {
		t.Error("a claim naming a source tree missed the component of that name")
	}
	if !got[0].Covers(forked) {
		t.Error("a claim naming a source tree missed a fork of it")
	}
	if got[0].Covers(elsewhere) {
		t.Error("a claim naming a source tree reached a component that merely starts the same")
	}
}

// csafDocument wraps a product tree and a list of vulnerabilities in the
// document a reader of the given category takes.
func csafDocument(category, tree, vulnerabilities string) string {
	return `{"document": {"category": "` + category + `", "csaf_version": "2.0",
	  "publisher": {"category": "vendor", "name": "Example"},
	  "title": "x", "tracking": {"id": "EX-1", "version": "1", "status": "final",
	    "current_release_date": "2026-09-01T00:00:00Z",
	    "initial_release_date": "2026-09-01T00:00:00Z",
	    "revision_history": [{"number": "1", "date": "2026-09-01T00:00:00Z", "summary": "First"}]}},
	 "product_tree": ` + tree + `,
	 "vulnerabilities": ` + vulnerabilities + `}`
}

// csafProducts is a tree defining count products, P0 onwards, with the groups
// given, and the list of the products' identifiers as a JSON array.
func csafProducts(count int, groups string) (tree, ids string) {
	var products, listed strings.Builder
	for i := range count {
		if i > 0 {
			products.WriteString(",")
			listed.WriteString(",")
		}
		fmt.Fprintf(&products, `{"product_id": "P%d", "name": "p%d",
		 "product_identification_helper": {"purl": "pkg:deb/debian/p%d@1.0"}}`, i, i, i)
		fmt.Fprintf(&listed, `"P%d"`, i)
	}
	tree = `{"full_product_names": [` + products.String() + `]`
	if groups != "" {
		tree += `, "product_groups": ` + groups
	}
	return tree + `}`, "[" + listed.String() + "]"
}

// bothCSAFReaders reads one document through the reader of each category.
// They share the walk, and each is asked for its bounds rather than having
// them assumed from the other.
func bothCSAFReaders(tree, vulnerabilities string, lim sbom.Limits) map[string]error {
	_, vex := sbom.ReadSuppressions(strings.NewReader(
		csafDocument("csaf_vex", tree, vulnerabilities)), lim)
	_, advisory := sbom.ReadAdvisory(strings.NewReader(
		csafDocument("csaf_security_advisory", tree, vulnerabilities)), lim)
	return map[string]error{"VEX": vex, "advisory": advisory}
}

func TestAGroupReferenceIsChargedWhatItStandsFor(t *testing.T) {
	// A reference to a group is one short identifier standing for every
	// product the group holds, and the distinct-identifier bound charges a
	// repeat of it nothing. Fifty products named through one group thirty
	// times is fifteen hundred entries from a few hundred bytes of flags.
	lim := sbom.Limits{MaxComponents: 100}
	_, ids := csafProducts(50, "")
	tree, _ := csafProducts(50, `[{"group_id": "G", "product_ids": `+ids+`}]`)
	vulnerabilities := func(groups string) string {
		return `[{"cve": "CVE-2026-1", "product_status": {"known_not_affected": ` + ids + `},
		  "flags": [{"label": "vulnerable_code_not_present", "group_ids": [` + groups + `]}]}]`
	}
	for reader, err := range bothCSAFReaders(tree, vulnerabilities(`"G"`), lim) {
		if err != nil {
			t.Errorf("the %s reader refused one reference to a group of fifty: %v", reader, err)
		}
	}
	references := strings.TrimSuffix(strings.Repeat(`"G",`, 30), ",")
	for reader, err := range bothCSAFReaders(tree, vulnerabilities(references), lim) {
		if err == nil {
			t.Errorf("the %s reader expanded a group of fifty thirty times over under a "+
				"bound of a hundred products", reader)
			continue
		}
		if !strings.Contains(err.Error(), "product limit") {
			t.Errorf("the %s refusal does not name the limit it hit: %v", reader, err)
		}
	}
}

func TestEveryClaimListingTheSameProductsIsCharged(t *testing.T) {
	// Each claim keeps its own list of the products under it, so a product
	// listed by eleven claims is eleven entries held while the set of distinct
	// identifiers stays at a hundred.
	lim := sbom.Limits{MaxComponents: 100}
	tree, ids := csafProducts(100, "")
	claims := func(count int) string {
		var out strings.Builder
		out.WriteString("[")
		for i := range count {
			if i > 0 {
				out.WriteString(",")
			}
			fmt.Fprintf(&out, `{"cve": "CVE-2026-%d", "product_status": {"fixed": %s}}`, i+1, ids)
		}
		return out.String() + "]"
	}
	for reader, err := range bothCSAFReaders(tree, claims(2), lim) {
		if err != nil {
			t.Errorf("the %s reader refused two claims about a hundred products: %v", reader, err)
		}
	}
	for reader, err := range bothCSAFReaders(tree, claims(11), lim) {
		if err == nil {
			t.Errorf("the %s reader held eleven lists of a hundred products under a bound "+
				"of a hundred", reader)
			continue
		}
		if !strings.Contains(err.Error(), "product limit") {
			t.Errorf("the %s refusal does not name the limit it hit: %v", reader, err)
		}
	}
}

func TestTheCVEIsTheIssuesNameWhereverTheDocumentStatesIt(t *testing.T) {
	// A producer chooses the key order. The other identifiers the issue goes
	// by are aliases whether they come before the CVE or after it.
	tree, _ := csafProducts(1, "")
	for _, order := range []struct{ name, keys string }{
		{"ids first", `"ids": [{"system_name": "GHSA", "text": "GHSA-aaaa-bbbb-cccc"}], "cve": "CVE-2026-1",`},
		{"cve first", `"cve": "CVE-2026-1", "ids": [{"system_name": "GHSA", "text": "GHSA-aaaa-bbbb-cccc"}],`},
	} {
		got, err := sbom.ReadSuppressions(strings.NewReader(csafDocument("csaf_vex", tree,
			`[{`+order.keys+` "product_status": {"known_not_affected": ["P0"]}}]`)), sbom.Limits{})
		if err != nil {
			t.Fatalf("%s: reading: %v", order.name, err)
		}
		if len(got) != 1 {
			t.Fatalf("%s: %d claims", order.name, len(got))
		}
		if got[0].Vulnerability != "CVE-2026-1" {
			t.Errorf("%s: the claim is about %q", order.name, got[0].Vulnerability)
		}
		if len(got[0].Aliases) != 1 || got[0].Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
			t.Errorf("%s: the claim also goes by %q", order.name, got[0].Aliases)
		}
	}
}

func TestAnIssueWithNoCVEIsNamedByItsFirstIdentifier(t *testing.T) {
	tree, _ := csafProducts(1, "")
	got, err := sbom.ReadSuppressions(strings.NewReader(csafDocument("csaf_vex", tree,
		`[{"ids": [{"system_name": "Example", "text": "EX-1"},
		           {"system_name": "GHSA", "text": "GHSA-aaaa-bbbb-cccc"}],
		  "product_status": {"known_not_affected": ["P0"]}}]`)), sbom.Limits{})
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if got[0].Vulnerability != "EX-1" {
		t.Errorf("the claim is about %q", got[0].Vulnerability)
	}
	if len(got[0].Aliases) != 1 || got[0].Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("the claim also goes by %q", got[0].Aliases)
	}
}

func TestWordsScopedByGroupStayScopedWhenTheTreeComesLast(t *testing.T) {
	// A group named before the tree that defines it has been read holds
	// nothing yet. Words scoped by it are about the products it holds once
	// the document is closed, and never about the whole claim.
	const vulnerabilities = `[{"cve": "CVE-2026-1",
	    "product_status": {"fixed": ["P1"], "known_not_affected": ["P2"]},
	    "flags": [{"label": "vulnerable_code_not_present", "group_ids": ["G1"]}],
	    "remediations": [{"category": "vendor_fix",
	      "details": "Upgrade to p1 1.0.", "group_ids": ["G1"]}]}]`
	const tree = `{"full_product_names": [
	      {"product_id": "P1", "name": "p1",
	       "product_identification_helper": {"purl": "pkg:deb/debian/p1@1.0"}},
	      {"product_id": "P2", "name": "p2",
	       "product_identification_helper": {"purl": "pkg:deb/debian/p2@1.0"}}],
	    "product_groups": [{"group_id": "G1", "product_ids": ["P1"]}]}`
	const head = `{"document": {"category": "csaf_security_advisory", "csaf_version": "2.0",
	  "publisher": {"category": "vendor", "name": "Example"},
	  "title": "x", "tracking": {"id": "EX-1"}}`
	got, err := sbom.ReadAdvisory(strings.NewReader(head+
		`, "vulnerabilities": `+vulnerabilities+`, "product_tree": `+tree+`}`), sbom.Limits{})
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(got.Claims) != 2 {
		t.Fatalf("%d claims", len(got.Claims))
	}
	for _, one := range got.Claims {
		switch one.Status {
		case sbom.AlreadyFixed:
			if one.Statement != "Upgrade to p1 1.0." {
				t.Errorf("the fixed claim says %q, and the group named its product", one.Statement)
			}
			if one.Justification != "vulnerable_code_not_present" {
				t.Errorf("the fixed claim is justified by %q", one.Justification)
			}
		case sbom.NotAffected:
			if one.Justification != "" {
				t.Errorf("the not-affected claim is justified by %q, a flag about another "+
					"product", one.Justification)
			}
		}
	}
}

func TestEveryEntryTheCSAFReaderKeepsIsCharged(t *testing.T) {
	// Each place the reader keeps an entry, repeated a thousand and one times
	// about one product. The distinct-identifier bound charges a repeat
	// nothing, so only the charge per entry held stops each of these: a
	// hundred products allow a thousand entries.
	lim := sbom.Limits{MaxComponents: 100}
	const product = `{"product_id": "P0", "name": "p0",
	  "product_identification_helper": {"purl": "pkg:deb/debian/p0@1.0"}}`
	repeat := func(count int, each func(i int) string) string {
		out := make([]string, count)
		for i := range out {
			out[i] = each(i)
		}
		return strings.Join(out, ",")
	}
	claim := func(extra string) string {
		return `[{"cve": "CVE-2026-1", "product_status": {"known_not_affected": ["P0"]}` +
			extra + `}]`
	}
	onlyProduct := func(int) string { return `{"full_product_names": [` + product + `]}` }
	noExtra := func(int) string { return claim("") }
	cases := []struct {
		name            string
		tree            func(n int) string
		vulnerabilities func(n int) string
	}{
		{
			name: "a product defined again",
			tree: func(n int) string {
				return `{"full_product_names": [` + repeat(n, func(int) string { return product }) + `]}`
			},
			vulnerabilities: noExtra,
		},
		{
			name: "a group holding no product",
			tree: func(n int) string {
				return `{"full_product_names": [` + product + `], "product_groups": [` +
					repeat(n, func(i int) string { return fmt.Sprintf(`{"group_id": "G%d"}`, i) }) + `]}`
			},
			vulnerabilities: noExtra,
		},
		{
			name: "a group member",
			tree: func(n int) string {
				return `{"full_product_names": [` + product + `], "product_groups": [
				  {"group_id": "G", "product_ids": [` + repeat(n, func(int) string { return `"P0"` }) + `]}]}`
			},
			vulnerabilities: noExtra,
		},
		{
			name: "an alias",
			tree: onlyProduct,
			vulnerabilities: func(n int) string {
				return claim(`, "ids": [` + repeat(n, func(int) string {
					return `{"system_name": "Example", "text": "EX-1"}`
				}) + `]`)
			},
		},
		{
			name: "a product a sentence names",
			tree: onlyProduct,
			vulnerabilities: func(n int) string {
				return claim(`, "flags": [{"label": "vulnerable_code_not_present",
				  "product_ids": [` + repeat(n, func(int) string { return `"P0"` }) + `]}]`)
			},
		},
		{
			name: "a group a sentence names",
			tree: func(int) string {
				return `{"full_product_names": [` + product + `], "product_groups": [{"group_id": "G"}]}`
			},
			vulnerabilities: func(n int) string {
				return claim(`, "flags": [{"label": "vulnerable_code_not_present",
				  "group_ids": [` + repeat(n, func(int) string { return `"G"` }) + `]}]`)
			},
		},
	}
	for _, c := range cases {
		for reader, err := range bothCSAFReaders(c.tree(1), c.vulnerabilities(1), lim) {
			if err != nil {
				t.Errorf("%s once: the %s reader refused it: %v", c.name, reader, err)
			}
		}
		for reader, err := range bothCSAFReaders(c.tree(1001), c.vulnerabilities(1001), lim) {
			if err == nil {
				t.Errorf("%s a thousand and one times: the %s reader held every one under a "+
					"bound of a hundred products", c.name, reader)
				continue
			}
			if !strings.Contains(err.Error(), "product limit") {
				t.Errorf("%s: the %s refusal does not name the limit it hit: %v", c.name, reader, err)
			}
		}
	}
}

func TestTheLastJustificationForTheWholeClaimStands(t *testing.T) {
	// A flag naming no product is about the whole claim, and a later one wins.
	tree, _ := csafProducts(1, "")
	got, err := sbom.ReadSuppressions(strings.NewReader(csafDocument("csaf_vex", tree,
		`[{"cve": "CVE-2026-1", "product_status": {"known_not_affected": ["P0"]},
		  "flags": [{"label": "component_not_present"},
		            {"label": "vulnerable_code_not_present"}]}]`)), sbom.Limits{})
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d claims", len(got))
	}
	if got[0].Justification != "vulnerable_code_not_present" {
		t.Errorf("the claim is justified by %q", got[0].Justification)
	}
}
