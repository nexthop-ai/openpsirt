package graph_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestWhatAPackageWasBuiltFromIsReadFromItsIdentifier(t *testing.T) {
	for _, c := range []struct {
		purl    string
		name    string
		version string
	}{
		{"pkg:deb/debian/acl@2.3.2-2%2Bb1?arch=amd64&upstream=acl%402.3.2-2", "acl", "2.3.2-2"},
		// A binary cut from a differently named source package. The bare name
		// is the whole of what is knowable, and it is the half that matching a
		// build's own claims needs.
		{"pkg:deb/debian/apt-transport-https@3.0.3?arch=amd64&upstream=apt", "apt", ""},
		{"pkg:deb/debian/bsdextrautils@2.41.5?upstream=util-linux", "util-linux", ""},
		// An epoch contains a colon, and a version may contain more besides —
		// so the name is cut at the last separator, not the first.
		{"pkg:deb/debian/auditd@1:4.0.2-2%2Bb2?upstream=audit%401:4.0.2-2", "audit", "1:4.0.2-2"},
		// Nothing to say.
		{"pkg:deb/debian/acl@2.3.2-2", "", ""},
		{"pkg:deb/debian/acl@2.3.2-2?arch=amd64&distro=debian-13", "", ""},
		{"", "", ""},
		// A qualifier that only looks like it.
		{"pkg:deb/debian/acl@2.3.2-2?upstreamish=no", "", ""},
	} {
		name, version := graph.UpstreamFromPurl(c.purl)
		if name != c.name || version != c.version {
			t.Errorf("%s\n  read as (%q, %q), want (%q, %q)", c.purl, name, version, c.name, c.version)
		}
	}
}

func TestOneDescriptionFillsWhatAnotherLeftOut(t *testing.T) {
	// Two descriptions of one package, which is what a merged inventory
	// produces. What the first said stands — two producers disagreeing is not
	// something this can settle — and what it did not say is taken.
	kept := graph.Described{Name: "acl", Version: "2.3.2-2+b1"}
	kept.FillFrom(graph.Described{
		CPE: "cpe:2.3:a:acl:acl:2.3.2:*:*:*:*:*:*:*", UpstreamName: "acl", UpstreamVersion: "2.3.2-2",
	})
	if kept.CPE == "" || kept.UpstreamName != "acl" || kept.UpstreamVersion != "2.3.2-2" {
		t.Errorf("gaps were not filled: %+v", kept)
	}

	stated := graph.Described{
		Name: "acl", Version: "2.3.2-2+b1",
		CPE: "cpe:first", UpstreamName: "first", UpstreamVersion: "1",
	}
	stated.FillFrom(graph.Described{CPE: "cpe:second", UpstreamName: "second", UpstreamVersion: "2"})
	if stated.CPE != "cpe:first" || stated.UpstreamName != "first" || stated.UpstreamVersion != "1" {
		t.Errorf("a later description overwrote an earlier one: %+v", stated)
	}
}

func TestAPackageIdentifierKeepsWhatIdentityThrowsAway(t *testing.T) {
	// Identity deliberately drops qualifiers, because they qualify rather than
	// identify. Somebody looking a package up needs exactly those: which
	// distribution release it was built for is what tells a package browser
	// which branch to answer from.
	for _, c := range []struct {
		purl string
		want graph.Parts
	}{
		{
			purl: "pkg:apk/alpine/busybox@1.37.0-r31?arch=x86_64&distro=alpine-3.24.1",
			want: graph.Parts{Type: "apk", Namespace: "alpine", Name: "busybox", Version: "1.37.0-r31", Distro: "alpine-3.24.1"},
		},
		{
			// A module path is several segments, and all but the last are the
			// namespace. Escapes are resolved: the same version arrives
			// spelled both ways from two producers.
			purl: "pkg:golang/github.com/docker/docker@v28.5.2%2Bincompatible",
			want: graph.Parts{Type: "golang", Namespace: "github.com/docker", Name: "docker", Version: "v28.5.2+incompatible"},
		},
		{
			// The type is case-insensitive by the specification; nothing else
			// is.
			purl: "pkg:GOLANG/Example.COM/Pkg@v1",
			want: graph.Parts{Type: "golang", Namespace: "Example.COM", Name: "Pkg", Version: "v1"},
		},
		{
			// A subpath follows the qualifiers and is neither one.
			purl: "pkg:deb/debian/busybox@1.35.0-4?distro=debian-12#src/main",
			want: graph.Parts{Type: "deb", Namespace: "debian", Name: "busybox", Version: "1.35.0-4", Distro: "debian-12"},
		},
		{purl: "pkg:cargo/openssl@0.10.55", want: graph.Parts{Type: "cargo", Name: "openssl", Version: "0.10.55"}},
		{purl: "pkg:apk/busybox", want: graph.Parts{Type: "apk", Name: "busybox"}},
		// Nothing readable rather than a guess: an identifier of another
		// scheme describes something this cannot resolve.
		{purl: "https://example.com/busybox", want: graph.Parts{}},
		{purl: "pkg:apk", want: graph.Parts{}},
		{purl: "", want: graph.Parts{}},
	} {
		if got := graph.PartsOfPurl(c.purl); got != c.want {
			t.Errorf("PartsOfPurl(%q) = %+v, want %+v", c.purl, got, c.want)
		}
	}
}
