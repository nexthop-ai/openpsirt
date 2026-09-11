package sbom_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// claims parses a suppression document written inline in a test.
func claims(t *testing.T, body string) []sbom.Suppression {
	t.Helper()
	got, err := sbom.ReadSuppressions(strings.NewReader(body), sbom.Limits{})
	if err != nil {
		t.Fatalf("read suppressions: %v", err)
	}
	return got
}

// statement wraps one claim in the document around it.
func statement(body string) string {
	return `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:x", "version": 1,
	 "statements": [` + body + `]}`
}

func TestReadsAPatchDerivedStatement(t *testing.T) {
	got, err := sbom.ReadSuppressions(fixture(t, "suppression-from-patch.openvex.json"), sbom.Limits{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("read %d claims, want 1", len(got))
	}
	claim := got[0]
	if claim.Vulnerability != "CVE-2017-1000487" {
		t.Errorf("claim is about %q", claim.Vulnerability)
	}
	if claim.Status != sbom.NotAffected || !claim.Status.Suppresses() {
		t.Errorf("status is %q", claim.Status)
	}
	if claim.Justification != "vulnerable_code_not_in_execute_path" {
		t.Errorf("justification is %q", claim.Justification)
	}
	if claim.Statement == "" {
		t.Error("what the build wrote alongside the claim was dropped")
	}
	if len(claim.Targets) != 1 || claim.Targets[0].Name != "thrift_0_14_1" {
		t.Errorf("targets are %+v", claim.Targets)
	}
}

func TestAPatchRecordsWhatItFixesAgainstTheComponentItIsOn(t *testing.T) {
	// The claim arrives attached to the component, so nothing has to work out
	// what it applies to — which is the failure mode of the separate document,
	// where a claim can name a source tree we cannot resolve to a package.
	doc, err := sbom.Read(fixture(t, "image.cdx.json"), sbom.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Suppressions) != 1 {
		t.Fatalf("read %d claims from the inventory, want 1", len(doc.Suppressions))
	}
	claim := doc.Suppressions[0]
	if claim.Vulnerability != "CVE-2026-31951" {
		t.Errorf("claim is about %q", claim.Vulnerability)
	}
	if claim.Origin != sbom.FromPedigree {
		t.Errorf("claim came from %q", claim.Origin)
	}
	// A carried patch means the vulnerable code was there and was fixed, which
	// is a different statement from it never having applied.
	if claim.Status != sbom.AlreadyFixed {
		t.Errorf("status is %q, want %q", claim.Status, sbom.AlreadyFixed)
	}
	if !strings.Contains(claim.Statement, "0007-cve-2026-31951.patch") {
		t.Errorf("the claim does not say which patch: %q", claim.Statement)
	}

	var frr graph.Described
	for _, c := range doc.Components {
		if c.Name == "frr" {
			frr = c
		}
	}
	if !claim.Covers(frr) {
		t.Error("the claim does not cover the component it was read from")
	}
}

func TestOnlyASecurityClaimIsReadFromAPatch(t *testing.T) {
	// A patch resolves defects and improvements as readily as vulnerabilities.
	doc := read(t, `{"bomFormat": "CycloneDX", "specVersion": "1.6",
	 "metadata": {"component": {"name": "p", "version": "1"}},
	 "components": [{"name": "frr", "version": "10.5.4-sonic-0", "purl": "pkg:deb/sonic/frr@10.5.4-sonic-0",
	   "pedigree": {"patches": [{"type": "unofficial", "diff": {"url": "file://p.patch"},
	     "resolves": [{"type": "defect", "id": "BUG-1"}, {"type": "security", "id": "CVE-2026-1"}]}]}}]}`)
	if len(doc.Suppressions) != 1 || doc.Suppressions[0].Vulnerability != "CVE-2026-1" {
		t.Fatalf("read %+v", doc.Suppressions)
	}
}

func TestQualifiersDoNotStopAClaimMatching(t *testing.T) {
	// A claim is written as the package and the version. The same package in
	// an inventory carries the architecture it was built for, so comparing the
	// two as written matches nothing.
	got := claims(t, statement(`{"vulnerability": {"name": "CVE-2026-1"}, "status": "not_affected",
	 "products": [{"@id": "pkg:deb/sonic/frr@10.5.4-sonic-0"}]}`))
	shipped := graph.Described{
		Purl: "pkg:deb/sonic/frr@10.5.4-sonic-0?arch=amd64", Name: "frr", Version: "10.5.4-sonic-0",
	}
	if !got[0].Covers(shipped) {
		t.Error("a claim naming the package and version did not cover it")
	}
}

func TestAClaimWithoutAVersionCoversEveryVersion(t *testing.T) {
	got := claims(t, statement(`{"vulnerability": {"name": "CVE-2026-1"}, "status": "not_affected",
	 "products": [{"@id": "pkg:deb/sonic/frr"}]}`))
	for _, version := range []string{"10.5.4-sonic-0", "10.6.1-sonic-2"} {
		shipped := graph.Described{Purl: "pkg:deb/sonic/frr@" + version + "?arch=amd64", Name: "frr", Version: version}
		if !got[0].Covers(shipped) {
			t.Errorf("a claim about every version did not cover %s", version)
		}
	}
	// It still says which package. A claim about one is not a claim about all.
	other := graph.Described{Purl: "pkg:deb/debian/libc6@2.41", Name: "libc6", Version: "2.41"}
	if got[0].Covers(other) {
		t.Error("a claim about one package covered another")
	}
}

func TestAClaimAgainstASourceTreeIsAsGoodAsItsName(t *testing.T) {
	// The build knows which packages came out of a source tree; we do not. The
	// most that can be said is that a component of the same name is the one
	// meant.
	got := claims(t, statement(`{"vulnerability": {"name": "CVE-2017-1000487"}, "status": "not_affected",
	 "products": [{"@id": "pkg:generic/thrift"}]}`))
	named := graph.Described{Purl: "pkg:deb/debian/libthrift@0.14.1", Name: "thrift", Version: "0.14.1"}
	forked := graph.Described{
		Purl: "pkg:deb/sonic/thriftshim@1.0", Name: "thriftshim", Version: "1.0", UpstreamName: "thrift",
	}
	elsewhere := graph.Described{Purl: "pkg:deb/debian/thrift-compiler@0.14.1", Name: "thrift-compiler", Version: "0.14.1"}

	if !got[0].Covers(named) {
		t.Error("a claim about a source tree missed the component of that name")
	}
	if !got[0].Covers(forked) {
		t.Error("a claim about a source tree missed a fork of it")
	}
	if got[0].Covers(elsewhere) {
		t.Error("a claim about a source tree reached a component that merely starts the same")
	}
}

func TestAClaimReachesEveryVersionOfWhatItNames(t *testing.T) {
	// One claim, however many places its component sits — the fan-out is done
	// where findings are, not here.
	got := claims(t, statement(`{"vulnerability": {"name": "CVE-2026-1"}, "status": "fixed",
	 "products": [{"@id": "pkg:deb/debian/libc6"}]}`))
	for _, version := range []string{"2.41", "2.36"} {
		shipped := graph.Described{Purl: "pkg:deb/debian/libc6@" + version, Name: "libc6", Version: version}
		if !got[0].Covers(shipped) {
			t.Errorf("a claim naming no version missed %s", version)
		}
	}
}

func TestTheOtherIdentifiersForAnIssueAreKept(t *testing.T) {
	// Which identifier a producer chose is a preference of whichever database
	// it consulted. A decision keyed on that one would lapse the day a scanner
	// changed its mind.
	got := claims(t, statement(`{"vulnerability": {"name": "CVE-2026-1", "aliases": ["GHSA-aaaa-bbbb-cccc"]},
	 "status": "not_affected", "products": [{"@id": "pkg:deb/debian/libc6"}]}`))
	if len(got[0].Aliases) != 1 || got[0].Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("aliases are %v", got[0].Aliases)
	}
}

func TestAVulnerabilityNamedAsPlainTextIsRead(t *testing.T) {
	// Earlier versions of the format name it as a string rather than as an
	// object, and a document written that way is perfectly well formed.
	got := claims(t, statement(`{"vulnerability": "CVE-2026-1", "status": "affected",
	 "products": [{"@id": "pkg:deb/debian/libc6"}]}`))
	if got[0].Vulnerability != "CVE-2026-1" {
		t.Errorf("claim is about %q", got[0].Vulnerability)
	}
	if got[0].Status.Suppresses() {
		t.Error("a claim that the build is affected suppressed a finding")
	}
}

func TestAStatusNothingCanReadIsRefused(t *testing.T) {
	// Ignoring it would let a build's judgment go missing silently, which is
	// what applying the claims here exists to prevent.
	_, err := sbom.ReadSuppressions(strings.NewReader(statement(
		`{"vulnerability": {"name": "CVE-2026-1"}, "status": "probably_fine",
		 "products": [{"@id": "pkg:deb/debian/libc6"}]}`)), sbom.Limits{})
	if err == nil {
		t.Fatal("an unreadable claim was accepted")
	}
	if !strings.Contains(err.Error(), "probably_fine") || !strings.Contains(err.Error(), "CVE-2026-1") {
		t.Errorf("refusal says neither what was wrong nor what it was about: %v", err)
	}
}

func TestAClaimAboutNothingIsRefused(t *testing.T) {
	_, err := sbom.ReadSuppressions(strings.NewReader(statement(
		`{"status": "not_affected", "products": [{"@id": "pkg:deb/debian/libc6"}]}`)), sbom.Limits{})
	if err == nil || !strings.Contains(err.Error(), "names no vulnerability") {
		t.Errorf("a claim naming no vulnerability was accepted: %v", err)
	}
}

func TestSomethingThatIsNotSuppressionsIsRefused(t *testing.T) {
	_, err := sbom.ReadSuppressions(fixture(t, "image.cdx.json"), sbom.Limits{})
	if err == nil || !strings.Contains(err.Error(), "not in a format this reads") {
		t.Errorf("an inventory was accepted as suppressions: %v", err)
	}
}

func TestMoreClaimsThanAllowedAreRefused(t *testing.T) {
	var b strings.Builder
	for i := range 40 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"vulnerability": {"name": "CVE-2026-1"}, "status": "not_affected",
		 "products": [{"@id": "pkg:deb/debian/libc6"}]}`)
	}
	_, err := sbom.ReadSuppressions(strings.NewReader(statement(b.String())), sbom.Limits{MaxStatements: 10})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("a document past the claim limit was accepted: %v", err)
	}
}

func TestPatchClaimsAreChargedAgainstTheClaimBound(t *testing.T) {
	// Every other way of making a claim is charged: both VEX readers refuse a
	// document past the statement limit. These were charged against nothing.
	//
	// The component bound does not stand in for it, because the claims hang
	// off one component's pedigree — so a document declaring a single
	// component can carry millions of them, and this is read in full inside
	// the upload request rather than by the worker afterwards.
	var resolves strings.Builder
	for i := 0; i < 60; i++ {
		if i > 0 {
			resolves.WriteString(",")
		}
		fmt.Fprintf(&resolves, `{"type": "security", "id": "CVE-2026-%d"}`, i)
	}
	body := `{"bomFormat": "CycloneDX", "specVersion": "1.6",
	 "metadata": {"component": {"name": "p", "version": "1"}},
	 "components": [{"name": "frr", "version": "1", "purl": "pkg:deb/sonic/frr@1",
	   "pedigree": {"patches": [{"type": "unofficial", "diff": {"url": "file://p.patch"},
	     "resolves": [` + resolves.String() + `]}]}}]}`

	// Read against a bound the document is past.
	if _, err := sbom.Read(strings.NewReader(body), sbom.Limits{
		MaxStatements: 50,
	}.OrDefault()); err == nil {
		t.Error("a document past the claim limit was read")
	} else if !strings.Contains(err.Error(), "claim limit") {
		t.Errorf("the refusal does not say which bound was passed: %v", err)
	}

	// And under it, the same document reads.
	doc, err := sbom.Read(strings.NewReader(body), sbom.Limits{
		MaxStatements: 100,
	}.OrDefault())
	if err != nil {
		t.Fatalf("a document inside the claim limit was refused: %v", err)
	}
	if len(doc.Suppressions) != 60 {
		t.Errorf("read %d claims, want 60", len(doc.Suppressions))
	}
}
