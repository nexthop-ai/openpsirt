package sbom_test

import (
	"io"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// advisoryText is one advisory from the corpus, as text, so that a test can
// state which half of a document it is taking away.
func advisoryText(t *testing.T, name string) string {
	t.Helper()
	body, err := io.ReadAll(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// readAdvisory reads one of the corpus documents.
func readAdvisory(t *testing.T, name string) sbom.Advisory {
	t.Helper()
	got, err := sbom.ReadAdvisory(strings.NewReader(advisoryText(t, name)), sbom.Limits{})
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return got
}

func TestAnAdvisoryIsReadAsEvidenceAboutTheVersionsItNames(t *testing.T) {
	got := readAdvisory(t, "advisory-platform-packages.csaf.json")
	if got.Identifier != "EXSA-2026:1001" {
		t.Errorf("the document is named %q, and that is what a revision of it replaces",
			got.Identifier)
	}
	if got.Publisher != "Example Platform Security" {
		t.Errorf("it was published by %q", got.Publisher)
	}
	if got.Title == "" {
		t.Error("the title is what a reader recognizes a serial number by")
	}
	if len(got.Claims) != 2 {
		t.Fatalf("%d claims, want one per status: %+v", len(got.Claims), got.Claims)
	}
	var fixed, notAffected *sbom.Suppression
	for i := range got.Claims {
		switch got.Claims[i].Status {
		case sbom.AlreadyFixed:
			fixed = &got.Claims[i]
		case sbom.NotAffected:
			notAffected = &got.Claims[i]
		}
	}
	if fixed == nil || notAffected == nil {
		t.Fatalf("the two statuses did not both come back: %+v", got.Claims)
	}
	// The claims point at composite identifiers, and what each one stands for
	// is the package rather than the platform it ships in.
	if len(fixed.Targets) != 1 ||
		fixed.Targets[0].Purl != "pkg:rpm/example/libnl-3-200@3.7.0-1.el9?arch=x86_64" {
		t.Errorf("the fixed claim points at %+v", fixed.Targets)
	}
	if fixed.Targets[0].Name != "libnl-3-200" {
		t.Errorf("the component it names is %q", fixed.Targets[0].Name)
	}
	// The prose is kept apart by status, the same way a VEX document's is.
	if !strings.Contains(fixed.Statement, "Upgrade to libnl-3-200") {
		t.Errorf("the fixed claim says %q", fixed.Statement)
	}
	if notAffected.Justification != "vulnerable_code_not_present" {
		t.Errorf("the not-affected claim gives %q", notAffected.Justification)
	}
}

func TestAClaimReachesTheVersionItNamesAndNoOther(t *testing.T) {
	// An advisory exists to name the version that carries the fix. Read as a
	// claim about the component's name alone it would answer for every version
	// of it, which is the opposite of what the publisher said.
	got := readAdvisory(t, "advisory-platform-packages.csaf.json")
	var fixed sbom.Suppression
	for _, one := range got.Claims {
		if one.Status == sbom.AlreadyFixed {
			fixed = one
		}
	}
	named := graph.Described{
		Purl: "pkg:rpm/example/libnl-3-200@3.7.0-1.el9", Name: "libnl-3-200",
		Version: "3.7.0-1.el9",
	}
	older := graph.Described{
		Purl: "pkg:rpm/example/libnl-3-200@3.6.0-1.el9", Name: "libnl-3-200",
		Version: "3.6.0-1.el9",
	}
	if !fixed.Covers(named) {
		t.Error("the claim missed the version it was made about")
	}
	if fixed.Covers(older) {
		t.Error("a claim about one version answered for another")
	}
}

func TestEveryProductStatusTheFormatDefinesIsRead(t *testing.T) {
	// A distribution states a recommended version and nothing else, so a
	// reader that knows four of the eight lists reads that document as making
	// no claim at all — accepted, recorded as nothing, and silently useless.
	got := readAdvisory(t, "advisory-recommended.csaf.json")
	if len(got.Claims) != 1 {
		t.Fatalf("%d claims from a document whose only status is recommended", len(got.Claims))
	}
	if got.Claims[0].Status != sbom.AlreadyFixed {
		t.Errorf("a recommended version reads as %q", got.Claims[0].Status)
	}
	if got.Claims[0].Targets[0].Name != "httpd" {
		t.Errorf("it points at %+v", got.Claims[0].Targets)
	}
}

func TestAnAdvisoryNamingProductsAndNoPackagesStillPlacesThem(t *testing.T) {
	// An equipment vendor names products rather than packages: no package
	// identifier anywhere in the tree, and the identifiers are serial numbers.
	// The most that can be said is that a component of that name is the one
	// meant, which is the same answer a claim against a source tree gets.
	got := readAdvisory(t, "advisory-named-products.csaf.json")
	if len(got.Claims) != 1 {
		t.Fatalf("%d claims: %+v", len(got.Claims), got.Claims)
	}
	if got.Claims[0].Status != sbom.Affected {
		t.Errorf("the claim reads as %q", got.Claims[0].Status)
	}
	if len(got.Claims[0].Targets) != 2 {
		t.Fatalf("it points at %+v", got.Claims[0].Targets)
	}
	for _, at := range got.Claims[0].Targets {
		if at.Purl != "" {
			t.Errorf("a product with no package identifier resolved to %q", at.Purl)
		}
		if at.Name == "" {
			t.Error("a product with no package identifier lost its name as well")
		}
	}
}

func TestAnOpaqueIdentifierResolvesThroughTheRelationshipThatMadeIt(t *testing.T) {
	// A network vendor's identifiers say nothing at all, and every one a claim
	// names is composed by a relationship. Resolved only through the tree, the
	// whole document points at nothing and is refused.
	got := readAdvisory(t, "advisory-opaque-products.csaf.json")
	if len(got.Claims) != 1 {
		t.Fatalf("%d claims: %+v", len(got.Claims), got.Claims)
	}
	names := make([]string, 0, 2)
	for _, at := range got.Claims[0].Targets {
		names = append(names, at.Name)
	}
	want := []string{"MeetingOS 10.3.2.0", "MeetingOS 10.3.4.0"}
	if len(names) != 2 {
		t.Fatalf("it points at %v", names)
	}
	for _, each := range want {
		if !strings.Contains(strings.Join(names, "|"), each) {
			t.Errorf("%q is not among %v", each, names)
		}
	}
}

func TestAVexDocumentIsRefusedAsAnAdvisory(t *testing.T) {
	// The two are read into the same claims and mean different things around
	// them: a statement set is a publisher's whole answer, and an advisory is
	// one announcement replaced by name. Read here, a VEX document would be
	// superseded under a name it does not carry.
	_, err := sbom.ReadAdvisory(strings.NewReader(csafVex), sbom.Limits{})
	if err == nil {
		t.Fatal("a VEX document was read as a security advisory")
	}
	if !strings.Contains(err.Error(), "VEX") {
		t.Errorf("the refusal does not say what it read: %v", err)
	}
}

func TestAnOpenVexDocumentIsRefusedAsAnAdvisory(t *testing.T) {
	// It shares no key with a CSAF document, so nothing it states is read at
	// all and the category stays empty.
	const openVex = `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.test/vex/1",
		"author":"Example","timestamp":"2026-09-01T00:00:00Z","version":1,
		"statements":[{"vulnerability":{"name":"CVE-2026-1"},
		"products":[{"@id":"pkg:deb/debian/libnl-3-200@3.7.0"}],"status":"not_affected",
		"justification":"vulnerable_code_not_present"}]}`
	if _, err := sbom.ReadAdvisory(strings.NewReader(openVex), sbom.Limits{}); err == nil {
		t.Error("an OpenVEX document was read as a security advisory")
	}
}

func TestAnAdvisoryWithNoNameOfItsOwnIsRefused(t *testing.T) {
	// The name is the key a revision replaces. Without it a second upload
	// would either replace nothing or replace everything that publisher has
	// issued, and neither is what happened.
	without := strings.Replace(advisoryText(t, "advisory-recommended.csaf.json"),
		`"id": "EXBA-2026:0591",`, "", 1)
	_, err := sbom.ReadAdvisory(strings.NewReader(without), sbom.Limits{})
	if err == nil {
		t.Fatal("an advisory with no tracking identifier was accepted")
	}
	if !strings.Contains(err.Error(), "tracking identifier") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

func TestAnAdvisoryNamingNoPublisherIsRefused(t *testing.T) {
	// Whose judgment it is decides what it supersedes and whose name stands
	// beside it on the finding.
	without := strings.Replace(advisoryText(t, "advisory-recommended.csaf.json"),
		`"name": "Example Distribution Security Team",`, "", 1)
	_, err := sbom.ReadAdvisory(strings.NewReader(without), sbom.Limits{})
	if err == nil {
		t.Fatal("an advisory naming no publisher was accepted")
	}
	if !strings.Contains(err.Error(), "publisher") {
		t.Errorf("the refusal does not say what is missing: %v", err)
	}
}

func TestAnAdvisoryPointingAtNothingIsRefused(t *testing.T) {
	// A claim we cannot place is a publisher's judgment going missing quietly.
	orphaned := strings.Replace(advisoryText(t, "advisory-recommended.csaf.json"),
		`"recommended": ["Example Distribution Linux 7:httpd-0:2.4.6-99.2.x86_64"]`,
		`"recommended": ["NOT-IN-THE-TREE"]`, 1)
	if _, err := sbom.ReadAdvisory(strings.NewReader(orphaned), sbom.Limits{}); err == nil {
		t.Error("a claim pointing at nothing the document defines was accepted")
	}
}

func TestARelationshipCountsAgainstTheProductLimit(t *testing.T) {
	// What a bound has to stop is the walk. A document composing millions of
	// identifiers is under a claim count and under a tree count, because it
	// states neither.
	lim := sbom.Limits{MaxComponents: 3}
	_, err := sbom.ReadAdvisory(
		strings.NewReader(advisoryText(t, "advisory-platform-packages.csaf.json")), lim)
	if err == nil {
		t.Fatal("a document naming more identifiers than the limit was read")
	}
	if !strings.Contains(err.Error(), "product limit") {
		t.Errorf("the refusal does not name the bound: %v", err)
	}
}

func TestACsafVexDocumentResolvesItsRelationshipsToo(t *testing.T) {
	// Every product identifier in a real distribution's VEX document is a
	// composite one. Resolved through the tree alone, such a document points
	// at nothing and is refused whole — so this is the VEX path's rule as much
	// as the advisory path's.
	vex := strings.Replace(advisoryText(t, "advisory-platform-packages.csaf.json"),
		`"category": "csaf_security_advisory"`, `"category": "csaf_vex"`, 1)
	claims, err := sbom.ReadSuppressions(strings.NewReader(vex), sbom.Limits{})
	if err != nil {
		t.Fatalf("reading a VEX document whose products are composed: %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("%d claims: %+v", len(claims), claims)
	}
}

func TestARelationshipsOwnIdentifierWinsOverThePackagesOwn(t *testing.T) {
	// A relationship may carry an identifier for the composite it makes, which
	// describes the package as that platform ships it — the distribution
	// qualifier is the part the package's own identifier cannot carry, and it
	// is what a component in an inventory actually looks like.
	got := readAdvisory(t, "advisory-recommended.csaf.json")
	if len(got.Claims) != 1 || len(got.Claims[0].Targets) != 1 {
		t.Fatalf("the document reads as %+v", got.Claims)
	}
	if want := "pkg:rpm/distribution/httpd@2.4.6-99.2?arch=x86_64&distro=linux-7"; got.Claims[0].Targets[0].Purl != want {
		t.Errorf("it points at %q, and the relationship said %q",
			got.Claims[0].Targets[0].Purl, want)
	}
}

func TestProseNamingAProductReachesTheClaimThatProductIsUnder(t *testing.T) {
	// An advisory's remediation names the packages to upgrade, and lists those
	// same packages as fixed. Read by category alone — a remediation argues
	// about something affected — the one sentence a triager wants lands on a
	// claim the document never made, and the fixed claim carries nothing.
	got := readAdvisory(t, "advisory-platform-packages.csaf.json")
	for _, one := range got.Claims {
		if one.Status == sbom.AlreadyFixed && one.Statement == "" {
			t.Error("the fixed claim carries none of the words written about it")
		}
		if one.Status == sbom.NotAffected &&
			strings.Contains(one.Statement, "Upgrade") {
			t.Errorf("the not-affected claim carries the remediation: %q", one.Statement)
		}
	}
}

func TestProseAboutOneProductWinsOverProseAboutTheWholeStatus(t *testing.T) {
	// A document may write both: a sentence about everything it lists, and a
	// sentence about one product under one status. The second is the more
	// precise of the two and is what the reader wants, and it cannot win if
	// the general one is put in place first.
	got := readAdvisory(t, "advisory-platform-packages.csaf.json")
	for _, one := range got.Claims {
		if one.Status != sbom.NotAffected {
			continue
		}
		if !strings.Contains(one.Statement, "not compiled into this package") {
			t.Errorf("the not-affected claim says %q, and the document wrote a "+
				"sentence about that product", one.Statement)
		}
	}
}

func TestAnAdvisoryIsBoundedBySizeDepthAndClaimCount(t *testing.T) {
	// A published document is somebody else's output arriving over a link we
	// do not control, exactly as a scan file is. The reader is opened here
	// rather than shared with the suppression path, so each bound it is meant
	// to carry is asked of it rather than assumed from the reader beside it.
	body := advisoryText(t, "advisory-platform-packages.csaf.json")
	// A second issue in the same document, so that a limit of one has
	// something to refuse. A zero limit is an unset one everywhere here.
	opens := strings.Index(body, `"vulnerabilities": [`) + len(`"vulnerabilities": [`)
	twice := body[:opens] + `{"cve": "CVE-2026-1099",
	  "product_status": {"fixed": ["BaseOS-9.4.0.GA:libnl-3-200-0:3.7.0-1.el9.x86_64"]}},` +
		body[opens:]
	for _, each := range []struct {
		bound string
		body  string
		lim   sbom.Limits
		says  string
	}{
		{"size", body, sbom.Limits{MaxBytes: 64}, "larger than"},
		{"depth", body, sbom.Limits{MaxDepth: 3}, "nests deeper"},
		{"claims", twice, sbom.Limits{MaxStatements: 1}, "limit"},
		{"products", body, sbom.Limits{MaxComponents: 3}, "product limit"},
	} {
		_, err := sbom.ReadAdvisory(strings.NewReader(each.body), each.lim)
		if err == nil {
			t.Errorf("a document past the %s bound was read", each.bound)
			continue
		}
		if !strings.Contains(err.Error(), each.says) {
			t.Errorf("the %s refusal reads %q, and does not say which bound it is",
				each.bound, err)
		}
	}
}

func TestARealSupplierAdvisoryReads(t *testing.T) {
	// Somebody else's output, unmodified. The three fixtures written here
	// reproduce shapes read out of real documents, which proves the reader
	// against shapes this project chose to write down — and a shape nobody
	// here thought of is exactly what that cannot cover.
	got := readAdvisory(t, "suse-su-2026_0005-1.json")
	if got.Identifier != "SUSE-SU-2026:0005-1" {
		t.Errorf("the document is named %q", got.Identifier)
	}
	if got.Publisher != "SUSE Product Security Team" {
		t.Errorf("it was published by %q", got.Publisher)
	}
	if len(got.Claims) != 1 {
		t.Fatalf("%d claims: %+v", len(got.Claims), got.Claims)
	}
	one := got.Claims[0]
	if one.Vulnerability != "CVE-2025-10158" {
		t.Errorf("the claim is about %q", one.Vulnerability)
	}
	// A recommended version is a fixed version. Four of the eight lists read,
	// this document makes no claim at all and is accepted saying nothing.
	if one.Status != sbom.AlreadyFixed {
		t.Errorf("a recommended version reads as %q", one.Status)
	}
	// Every identifier the claim names is composed by a relationship, so a
	// reader resolving through the tree alone refuses the whole document.
	if len(one.Targets) != 4 {
		t.Fatalf("it points at %+v", one.Targets)
	}
	for _, at := range one.Targets {
		if at.Name != "rsync" {
			t.Errorf("a target resolved to %+v rather than the package", at)
		}
		if !strings.HasPrefix(at.Purl, "pkg:rpm/suse/rsync@3.1.3-3.34.1") {
			t.Errorf("a target carries %q", at.Purl)
		}
	}
	// The words written about the products it names, rather than the ones
	// written about the status at large.
	if !strings.Contains(one.Statement, "zypper patch") {
		t.Errorf("the claim says %q, and the remediation is the part worth having",
			one.Statement)
	}
}
