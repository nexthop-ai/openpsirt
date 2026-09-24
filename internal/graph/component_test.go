// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
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

// Two writers describing the same component are agreeing, not colliding.
//
// The lookup is inside the caller's transaction, which says nothing about
// another transaction against another target finding the same component
// absent at the same moment. A unique violation is not retryable, so the
// loser did not retry: its whole scan apply failed and the producer was told
// its upload could not be read, for a component that is now present. Two
// replicas reading two scans at once is the shipped arrangement, and a
// portfolio first meeting a shared dependency is exactly when it happens.
//
// The race is staged rather than run: the row is written directly, the way
// the other writer would have written it, and then a set still believing it
// absent is written over the top.
func TestTwoWritersInterningOneComponentBothSucceed(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		shared := graph.Described{
			Purl: "pkg:deb/debian/openssl@3.0.11-1", Name: "openssl", Version: "3.0.11-1",
		}
		fresh := graph.Described{
			Purl: "pkg:deb/debian/zlib1g@1.3", Name: "zlib1g", Version: "1.3",
		}

		components := graph.NewComponents(f.db.DB)
		written, err := components.Intern(ctx, []graph.Described{shared})
		if err != nil {
			t.Fatal(err)
		}
		theirs := written[shared.Identity()]
		if theirs == 0 {
			t.Fatal("the first writer recorded nothing")
		}

		// The loser of the race read before that row existed,
		// so it writes both, and one of them is already there.
		if err := database.InBatchesKeeping(ctx, f.db.DB, []graph.Component{
			{
				Identity: shared.Identity(), Purl: shared.Purl, Name: shared.Name,
				Version: shared.Version, NameFolded: graph.Folded(shared.Name),
				FoldKey: shared.FoldKey(), FirstSeenAt: time.Now().UTC(),
			},
			{
				Identity: fresh.Identity(), Purl: fresh.Purl, Name: fresh.Name,
				Version: fresh.Version, NameFolded: graph.Folded(fresh.Name),
				FoldKey: fresh.FoldKey(), FirstSeenAt: time.Now().UTC(),
			},
		}); err != nil {
			t.Fatalf("the writer that lost the race failed: %v", err)
		}

		// One row for the shared component, still the first writer's, and the
		// new one written.
		after, err := components.Intern(ctx, []graph.Described{shared, fresh})
		if err != nil {
			t.Fatal(err)
		}
		if after[shared.Identity()] != theirs {
			t.Errorf("the shared component is now %d, was %d: a second row was written",
				after[shared.Identity()], theirs)
		}
		if after[fresh.Identity()] == 0 {
			t.Error("the component that was new was not written")
		}
	})
}

func TestALaterReportFillsInWhoSuppliedAComponent(t *testing.T) {
	// Reports arrive in an order nobody controls, and one producer states a
	// supplier where another states none. Written only on the insert that first
	// interns a component, a component first seen through the quieter producer
	// never got one however many later scans said who it was — and the screen
	// read "not stated" permanently.
	//
	// The rule every other field two reports can disagree about already
	// follows: a later one fills in what an earlier one did not know, and
	// overwrites nothing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		quiet := graph.Described{
			Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0",
		}
		components := graph.NewComponents(f.db.DB)
		if _, err := components.Intern(ctx, []graph.Described{quiet}); err != nil {
			t.Fatal(err)
		}

		said := quiet
		said.Supplier = "Debian Curl Maintainers"
		if _, err := components.Intern(ctx, []graph.Described{said}); err != nil {
			t.Fatal(err)
		}
		if got := supplierOf(t, f, quiet.Identity()); got != "Debian Curl Maintainers" {
			t.Errorf("after a report stating one, the supplier is %q", got)
		}

		// And nothing overwrites it: a third report naming somebody else leaves
		// what is stored alone, or what is held would depend on which scan ran
		// last.
		other := quiet
		other.Supplier = "Somebody else"
		if _, err := components.Intern(ctx, []graph.Described{other}); err != nil {
			t.Fatal(err)
		}
		if got := supplierOf(t, f, quiet.Identity()); got != "Debian Curl Maintainers" {
			t.Errorf("a later report overwrote the supplier with %q", got)
		}
	})
}

// supplierOf reads back who a component is recorded as supplied by.
func supplierOf(t *testing.T, f *fixture, identity string) string {
	t.Helper()
	var said string
	err := f.db.DB.NewSelect().
		TableExpr("\"component\" AS \"c\"").
		ColumnExpr("COALESCE(c.supplier, '')").
		Where("c.identity = ?", identity).
		Scan(t.Context(), &said)
	if err != nil {
		t.Fatalf("read the supplier: %v", err)
	}
	return said
}

func TestALicenseIsWrittenOnTheInsertAndFilledInByALaterReport(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		components := graph.NewComponents(f.db.DB)

		stated := graph.Described{
			Purl: "pkg:deb/debian/zlib@1.3", Name: "zlib", Version: "1.3", License: "Zlib",
		}
		quiet := graph.Described{
			Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0",
		}
		if _, err := components.Intern(ctx, []graph.Described{stated, quiet}); err != nil {
			t.Fatal(err)
		}
		if got := licenseOf(t, f, stated.Identity()); got != "Zlib" {
			t.Errorf("a new component carries the license %q", got)
		}

		said := quiet
		said.License = "curl"
		if _, err := components.Intern(ctx, []graph.Described{said}); err != nil {
			t.Fatal(err)
		}
		if got := licenseOf(t, f, quiet.Identity()); got != "curl" {
			t.Errorf("after a report stating one, the license is %q", got)
		}

		// Nothing overwrites it, for the reason a supplier is not overwritten.
		other := quiet
		other.License = "MIT"
		if _, err := components.Intern(ctx, []graph.Described{other}); err != nil {
			t.Fatal(err)
		}
		if got := licenseOf(t, f, quiet.Identity()); got != "curl" {
			t.Errorf("a later report overwrote the license with %q", got)
		}
	})
}

// licenseOf reads back the license a component is recorded under.
func licenseOf(t *testing.T, f *fixture, identity string) string {
	t.Helper()
	var said string
	err := f.db.DB.NewSelect().
		TableExpr("\"component\" AS \"c\"").
		ColumnExpr("COALESCE(c.license, '')").
		Where("c.identity = ?", identity).
		Scan(t.Context(), &said)
	if err != nil {
		t.Fatalf("read the license: %v", err)
	}
	return said
}
