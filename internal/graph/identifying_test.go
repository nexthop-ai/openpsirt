// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// deb is a Debian package identifier for a name at a version, as SONiC writes
// one.
func deb(name, version string) string {
	return "pkg:deb/debian/" + name + "@" + version + "?arch=amd64&distro=debian-13"
}

func TestANameHoldingItsOwnReleaseIsIdentifiedWithoutIt(t *testing.T) {
	for _, c := range []struct {
		why, name, version, purl string
		// same is whether the name is identified as it stands.
		same bool
		// as is another name and version the first must be identified with,
		// where there is one.
		asName, asVersion, asPurl string
	}{
		{why: "the kernel image", name: "linux-image-6.12.41+deb13-sonic-amd64-unsigned", version: "6.12.41-1",
			purl:   deb("linux-image-6.12.41%2Bdeb13-sonic-amd64-unsigned", "6.12.41-1"),
			asName: "linux-image-6.12.94+deb13-sonic-amd64-unsigned", asVersion: "6.12.94-1",
			asPurl: deb("linux-image-6.12.94%2Bdeb13-sonic-amd64-unsigned", "6.12.94-1")},
		{why: "the kernel headers", name: "linux-headers-6.12.41+deb13-sonic-amd64", version: "6.12.41-1",
			purl:   deb("linux-headers-6.12.41%2Bdeb13-sonic-amd64", "6.12.41-1"),
			asName: "linux-headers-6.12.94+deb13-sonic-amd64", asVersion: "6.12.94-1",
			asPurl: deb("linux-headers-6.12.94%2Bdeb13-sonic-amd64", "6.12.94-1")},
		{why: "the common headers, under an identifier naming a commit", name: "linux-headers-6.12.41+deb13-common-sonic",
			version: "6.12.41-1", purl: "pkg:github/sonic-net/sonic-linux-kernel@5b0ee9f5fb19",
			asName: "linux-headers-6.12.94+deb13-common-sonic", asVersion: "6.12.94-1",
			asPurl: "pkg:github/sonic-net/sonic-linux-kernel@0c3f1d2e7a90"},
		{why: "the kernel build tools", name: "linux-kbuild-6.12.41+deb13", version: "6.12.41-1",
			purl:   deb("linux-kbuild-6.12.41%2Bdeb13", "6.12.41-1"),
			asName: "linux-kbuild-6.12.94+deb13", asVersion: "6.12.94-1",
			asPurl: deb("linux-kbuild-6.12.94%2Bdeb13", "6.12.94-1")},
		{why: "a Debian epoch and revision", name: "foo-2.3", version: "1:2.3-4+b1", purl: deb("foo-2.3", "1%3A2.3-4%2Bb1"),
			asName: "foo-2.4", asVersion: "1:2.4-1", asPurl: deb("foo-2.4", "1%3A2.4-1")},
		{why: "an RPM epoch and release", name: "kernel-5.14.0", version: "2:5.14.0-427.el9",
			purl:   "pkg:rpm/redhat/kernel-5.14.0@2:5.14.0-427.el9",
			asName: "kernel-5.14.1", asVersion: "5.14.1-1.el9", asPurl: "pkg:rpm/redhat/kernel-5.14.1@5.14.1-1.el9"},
		{why: "an Alpine revision", name: "py3-foo-1.2", version: "1.2-r3", purl: "pkg:apk/alpine/py3-foo-1.2@1.2-r3",
			asName: "py3-foo-1.3", asVersion: "1.3-r0", asPurl: "pkg:apk/alpine/py3-foo-1.3@1.3-r0"},
		{why: "a PEP 440 local label", name: "torch-2.1.0", version: "2.1.0+cu121", purl: "pkg:pypi/torch-2.1.0@2.1.0%2Bcu121",
			asName: "torch-2.2.0", asVersion: "2.2.0+cu121", asPurl: "pkg:pypi/torch-2.2.0@2.2.0%2Bcu121"},
		{why: "no package identifier", name: "linux-image-6.12.41-amd64", version: "6.12.41-1",
			asName: "linux-image-6.12.94-amd64", asVersion: "6.12.94-1"},
		{why: "the release at the end", name: "openjdk-17.0.12", version: "17.0.12", purl: "pkg:generic/openjdk-17.0.12@17.0.12",
			asName: "openjdk-17.0.13", asVersion: "17.0.13", asPurl: "pkg:generic/openjdk-17.0.13@17.0.13"},
		{why: "the release at the start", name: "6.12.41-kbuild", version: "6.12.41-1", purl: deb("6.12.41-kbuild", "6.12.41-1"),
			asName: "6.12.94-kbuild", asVersion: "6.12.94-1", asPurl: deb("6.12.94-kbuild", "6.12.94-1")},

		{why: "an interface number in a library", name: "libssl3", version: "3.5.1-1", purl: deb("libssl3", "3.5.1-1"), same: true},
		{why: "a language version in an interpreter", name: "python3.11", version: "3.11.2-6+deb12u6",
			purl: deb("python3.11", "3.11.2-6%2Bdeb12u6"), same: true},
		{why: "a major version in a runtime", name: "openjdk-17-jre", version: "17.0.12+7-2~deb12u1",
			purl: deb("openjdk-17-jre", "17.0.12%2B7-2~deb12u1"), same: true},
		{why: "another package's version", name: "kernel-mft-dkms-modules-6.12.41+deb13-sonic-amd64", version: "4.36.0",
			purl: "pkg:deb/sonic/kernel-mft-dkms-modules-6.12.41%2Bdeb13-sonic-amd64@4.36.0", same: true},
		{why: "a digit before the release", name: "lib16.12.41-x", version: "6.12.41-1", purl: deb("lib16.12.41-x", "6.12.41-1"), same: true},
		{why: "a digit after the release", name: "lib-6.12.410", version: "6.12.41-1", purl: deb("lib-6.12.410", "6.12.41-1"), same: true},
		{why: "a placeholder inside another version", name: "libsaibcm_dnx_15.2.0.0.0.0.16.2_amd64.deb", version: "0.0.0",
			purl: "pkg:generic/libsaibcm_dnx_15.2.0.0.0.0.16.2_amd64.deb@0.0.0", same: true},
		{why: "a number a dot carries on", name: "openssl-1.1.1", version: "1.1", purl: deb("openssl-1.1.1", "1.1"), same: true},
		{why: "a letter after the release", name: "lib-1.2rc", version: "1.2-1", purl: deb("lib-1.2rc", "1.2-1"), same: true},
		{why: "the release and nothing else", name: "6.12.41", version: "6.12.41-1", purl: deb("6.12.41", "6.12.41-1"), same: true},
		{why: "the version and nothing else", name: "2.0", version: "2.0", same: true},
		{why: "a semantic pre-release", name: "foo-1.0.0", version: "1.0.0-rc.1", purl: "pkg:npm/foo-1.0.0@1.0.0-rc.1", same: true},
		{why: "no version", name: "foo-1.0", purl: "pkg:generic/foo-1.0", same: true},
		{why: "a version that is a word", name: "foo-UNKNOWN", version: "UNKNOWN", purl: "pkg:generic/foo-UNKNOWN", same: false,
			asName: "foo-latest", asVersion: "latest", asPurl: "pkg:generic/foo-latest"},
	} {
		t.Run(c.why, func(t *testing.T) {
			got := graph.IdentifyingName(c.name, c.version, c.purl)
			if c.same && got != c.name {
				t.Errorf("%q at %q is identified as %q, want its name as it stands", c.name, c.version, got)
			}
			if !c.same && got == c.name {
				t.Errorf("%q at %q is identified by its name as it stands, want its release taken out", c.name, c.version)
			}
			if c.asName != "" {
				if as := graph.IdentifyingName(c.asName, c.asVersion, c.asPurl); as != got {
					t.Errorf("%q at %q is identified as %q and %q at %q as %q, want one name",
						c.name, c.version, got, c.asName, c.asVersion, as)
				}
			}
		})
	}
}

func TestANameWithItsReleaseTakenOutMatchesNoNameAsItStands(t *testing.T) {
	// The kernel renamed by its upgrade is one component; a package that
	// happens to be called what is left of its name is another.
	kernel := graph.IdentifyingName("linux-image-6.12.41+deb13-amd64", "6.12.41-1",
		deb("linux-image-6.12.41%2Bdeb13-amd64", "6.12.41-1"))
	for _, other := range []string{"linux-image-+deb13-amd64", "linux-image--+deb13-amd64", "linux-image-deb13-amd64"} {
		if graph.IdentifyingName(other, "1.0-1", deb(other, "1.0-1")) == kernel {
			t.Errorf("%q is identified as the kernel", other)
		}
	}
}

func TestEveryPlaceANameHoldsItsReleaseIsTakenOut(t *testing.T) {
	one := graph.IdentifyingName("foo-1.0-bar-1.0", "1.0-1", deb("foo-1.0-bar-1.0", "1.0-1"))
	two := graph.IdentifyingName("foo-2.0-bar-2.0", "2.0-1", deb("foo-2.0-bar-2.0", "2.0-1"))
	if one != two {
		t.Errorf("a name holding its release twice reads %q and %q at two releases, want one name", one, two)
	}
	// The release found again past a match that is not a token.
	if got := graph.IdentifyingName("x1.0-1.0", "1.0", "pkg:generic/x@1.0"); got == "x1.0-1.0" {
		t.Errorf("the release standing as a token after one that does not is kept in %q", got)
	}
}
