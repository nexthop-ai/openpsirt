package finding

import (
	"net/url"
	"strings"
	"testing"
)

// The addresses these produce are read by a person and followed in a browser,
// so what is pinned here is that a link points where its name says and that
// nothing a producer wrote can steer it somewhere else.

func TestAnIssueResolvesToItsOwnRecordAndNotOnlyToWhatAScannerPointedAt(t *testing.T) {
	// The whole reason these are derived: a scanner hands over whatever its
	// data carried, which for a package matched by identifier is often another
	// distribution's write-up. The identifier names a record on its own.
	got := links("CVE-2025-60876", nil, "pkg:apk/alpine/busybox@1.37.0-r31?arch=x86_64&distro=alpine-3.24.1")

	want := []Link{
		{URL: "https://www.cve.org/CVERecord?id=CVE-2025-60876", Name: "CVE record"},
		{URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-60876", Name: "NVD"},
		{URL: "https://security.alpinelinux.org/vuln/CVE-2025-60876", Name: "Alpine security tracker"},
		{URL: "https://pkgs.alpinelinux.org/packages?branch=v3.24&name=busybox", Name: "Alpine package"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d links, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("link %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestAnIdentifierThisDeploymentMintedResolvesToNothing(t *testing.T) {
	// A flaw recorded here is filed under a name this deployment invented
	// . No public record describes it, and a link offered anyway would
	// land on somebody else's page about something else — or on a page
	// about nothing, which reads as the record being missing rather than
	// private.
	for _, identifier := range []string{
		"OPENPSIRT-2026-0001", "CVE-2025", "CVE-YYYY-1234", "GHSA-not-a-real-one",
		"cve-2025-60876", " CVE-2025-60876 extra",
	} {
		for _, link := range links(identifier, nil, "") {
			t.Errorf("%q produced %+v, want no record", identifier, link)
		}
	}
}

func TestTheDistributionIsAskedAboutTheIssueAndTheEcosystemAboutThePackage(t *testing.T) {
	// The question a distribution's package always raises is whether a
	// backported fix is already in the release it ships, and the
	// distribution's own tracker is the only thing that answers it.
	for _, c := range []struct {
		name  string
		purl  string
		wants []string
	}{
		{
			name: "debian",
			purl: "pkg:deb/debian/busybox@1.35.0-4?distro=debian-12",
			wants: []string{
				"https://security-tracker.debian.org/tracker/CVE-2025-1000",
				"https://packages.debian.org/busybox",
			},
		},
		{
			name:  "ubuntu",
			purl:  "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-22.04",
			wants: []string{"https://ubuntu.com/security/CVE-2025-1000", "https://launchpad.net/ubuntu/+source/openssl"},
		},
		{
			name:  "red hat",
			purl:  "pkg:rpm/redhat/openssl@3.0.7-1.el9?distro=rhel-9",
			wants: []string{"https://access.redhat.com/security/cve/cve-2025-1000"},
		},
		{
			name:  "go module",
			purl:  "pkg:golang/github.com/docker/docker@v28.5.2%2Bincompatible",
			wants: []string{"https://pkg.go.dev/github.com/docker/docker@v28.5.2+incompatible"},
		},
		{
			name:  "npm scope",
			purl:  "pkg:npm/%40types/node@22.1.0",
			wants: []string{"https://www.npmjs.com/package/@types/node/v/22.1.0"},
		},
		{
			name:  "maven",
			purl:  "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
			wants: []string{"https://central.sonatype.com/artifact/org.apache.logging.log4j/log4j-core/2.14.1"},
		},
		{
			name:  "crate",
			purl:  "pkg:cargo/openssl@0.10.55",
			wants: []string{"https://crates.io/crates/openssl/0.10.55"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var have []string
			for _, link := range links("CVE-2025-1000", nil, c.purl) {
				have = append(have, link.URL)
			}
			for _, want := range c.wants {
				if !includes(have, want) {
					t.Errorf("want %q among %v", want, have)
				}
			}
		})
	}
}

func TestAPackageKindNothingHereKnowsProducesNoGuess(t *testing.T) {
	// A link that lands on a search page for the wrong thing costs more than
	// no link, because it is followed before it is disbelieved.
	for _, purl := range []string{
		"pkg:oci/openpsirt@sha256%3Aabc", "pkg:generic/busybox@1.37.0",
		"pkg:swift/github.com/x/y@1.0", "not-an-identifier", "", "pkg:",
	} {
		for _, link := range links("CVE-2025-1000", nil, purl) {
			if !strings.HasPrefix(link.URL, "https://www.cve.org/") &&
				!strings.HasPrefix(link.URL, "https://nvd.nist.gov/") {
				t.Errorf("%q produced %+v, want only the issue's own records", purl, link)
			}
		}
	}
}

func TestNothingAProducerWroteCanSteerALinkOffItsHost(t *testing.T) {
	// Component names and versions come out of a third party's inventory .
	// Escaping is what keeps one of them a path segment rather than a way
	// to reach a different site, a different path, or a query somebody
	// else's page would read.
	hostile := []string{
		"pkg:cargo/..%2F..%2Fevil@1.0",
		"pkg:cargo/evil?x@1.0#frag",
		"pkg:pypi/a b@1 0",
		"pkg:apk/alpine/x@1?distro=alpine-3.24.1&name=y",
		"pkg:golang/example.com%2F..%2Fadmin/pkg@v1",
		"pkg:cargo/..@1.0",
		"pkg:cargo/openssl@..",
		"pkg:golang/../admin@v1",
		"pkg:npm/%40scope/..@1.0",
	}
	for _, purl := range hostile {
		for _, link := range links("CVE-2025-1000", nil, purl) {
			parsed, err := url.Parse(link.URL)
			if err != nil {
				t.Errorf("%q produced an unparseable %q: %v", purl, link.URL, err)
				continue
			}
			if parsed.Scheme != "https" {
				t.Errorf("%q produced scheme %q", purl, parsed.Scheme)
			}
			for _, part := range strings.Split(parsed.EscapedPath(), "/") {
				if part != "" && strings.Trim(part, ".") == "" {
					t.Errorf("%q produced a path a browser resolves away: %q", purl, parsed.EscapedPath())
				}
			}
			if parsed.Host == "" || strings.ContainsAny(parsed.Host, "/@") {
				t.Errorf("%q produced host %q", purl, parsed.Host)
			}
		}
	}
}

func TestTheOtherNamesAnIssueGoesByResolveToo(t *testing.T) {
	// One issue is often two names, and the record under each says different
	// things — which is the reason both are kept.
	got := links("CVE-2025-1000", []string{"GHSA-2xxx-3xxx-4xxx", "CVE-2025-1000"}, "")

	var ghsa, duplicate int
	for _, link := range got {
		if link.URL == "https://github.com/advisories/GHSA-2xxx-3xxx-4xxx" {
			ghsa++
			if !strings.Contains(link.Name, "GHSA-2xxx-3xxx-4xxx") {
				t.Errorf("the alias's link is named %q, which does not say which name it answers", link.Name)
			}
		}
		if link.URL == "https://www.cve.org/CVERecord?id=CVE-2025-1000" {
			duplicate++
		}
	}
	if ghsa != 1 {
		t.Errorf("the alias resolved %d times, want once", ghsa)
	}
	// An alias repeating the issue's own name is one address twice, and a
	// reader learns nothing from the second.
	if duplicate != 1 {
		t.Errorf("the issue's record appears %d times, want once", duplicate)
	}
}

func TestAnAlpineBranchIsTheReleaseSeriesRatherThanTheBuild(t *testing.T) {
	// The package browser is organized by branch. Without a usable one the
	// name still resolves, across every branch at once, which is a worse
	// answer rather than a wrong one.
	for distro, want := range map[string]string{
		"alpine-3.24.1": "v3.24",
		"alpine-3.24":   "v3.24",
		"alpine-edge":   "",
		"alpine-":       "",
		"alpine":        "",
		"":              "",
	} {
		if got := alpineBranch(distro); got != want {
			t.Errorf("alpineBranch(%q) = %q, want %q", distro, got, want)
		}
	}
}

func includes(all []string, want string) bool {
	for _, have := range all {
		if have == want {
			return true
		}
	}
	return false
}
