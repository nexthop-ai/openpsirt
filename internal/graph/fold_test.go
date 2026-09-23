// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// described is a component as an inventory states it, for the tests below.
func described(purl, name, version, upstream, upstreamVersion string) graph.Described {
	return graph.Described{
		Purl: purl, Name: name, Version: version,
		UpstreamName: upstream, UpstreamVersion: upstreamVersion,
	}
}

func TestSiblingsOfOneSourcePackageFold(t *testing.T) {
	// The case the fold exists for: a distribution cuts several binaries from
	// one source package and they move together, so upgrading them is one act
	// rather than three that can disagree.
	curl := described("pkg:deb/debian/curl@8.14.1-2?distro=debian-13",
		"curl", "8.14.1-2", "curl", "8.14.1-2")
	lib4 := described("pkg:deb/debian/libcurl4t64@8.14.1-2?distro=debian-13",
		"libcurl4t64", "8.14.1-2", "curl", "8.14.1-2")
	lib3 := described("pkg:deb/debian/libcurl3t64-gnutls@8.14.1-2?distro=debian-13",
		"libcurl3t64-gnutls", "8.14.1-2", "curl", "8.14.1-2")

	if curl.FoldKey() != lib4.FoldKey() || curl.FoldKey() != lib3.FoldKey() {
		t.Error("three binaries of one source package at one version are three folds")
	}
	// And the fold is not the identity. Every record hangs off identity, and
	// nothing may move when the grouping does.
	if curl.Identity() == lib4.Identity() {
		t.Error("two components of one fold share an identity")
	}
}

func TestOneSourceAtTwoVersionsStaysTwoFolds(t *testing.T) {
	// Measured on a public switch operating-system image, and the collision
	// that made the source package's name alone unusable as the key: one build
	// carrying the kernel image at 6.12.41-1 with 5,088 issues, beside the
	// perf and header packages at 6.12.107-1 with 607 and none. Folded on the
	// name, the row would say one bump closes all of it, and one of the two
	// versions already carries the fix.
	image := described("pkg:deb/debian/linux-image-6.12.41-amd64@6.12.41-1?distro=debian-13",
		"linux-image-6.12.41-amd64", "6.12.41-1", "linux", "6.12.41-1")
	perf := described("pkg:deb/debian/linux-perf@6.12.107-1?distro=debian-13",
		"linux-perf", "6.12.107-1", "linux", "6.12.107-1")

	if image.FoldKey() == perf.FoldKey() {
		t.Error("one source package at two versions folded into one bump")
	}
}

func TestTwoEcosystemsUsingOneNameStayTwoFolds(t *testing.T) {
	// protobuf, setuptools, lxml and requests are each a Debian package and a
	// package of the same name published to a language index, at different
	// versions. The package type is what tells them apart.
	deb := described("pkg:deb/debian/python3-protobuf@3.21.12-11?distro=debian-13",
		"python3-protobuf", "3.21.12-11", "protobuf", "3.21.12-11")
	pypi := described("pkg:pypi/protobuf@5.29.6", "protobuf", "5.29.6", "", "")

	if deb.FoldKey() == pypi.FoldKey() {
		t.Error("a distribution package and a language index package folded together")
	}
}

func TestTwoDistributionsUsingOneNameStayTwoFolds(t *testing.T) {
	// busybox: Debian's at 1:1.37.0-6+b8 and Alpine's three at 1.37.0-r31.
	// One package type, one source package name, two distributions.
	debian := described("pkg:deb/debian/busybox@1:1.37.0-6%2Bb8?distro=debian-13",
		"busybox", "1:1.37.0-6+b8", "busybox", "1:1.37.0-6+b8")
	alpine := described("pkg:apk/alpine/busybox@1.37.0-r31?distro=alpine-3.24.1",
		"busybox", "1.37.0-r31", "busybox", "1.37.0-r31")

	if debian.FoldKey() == alpine.FoldKey() {
		t.Error("two distributions' packages of one name folded together")
	}
}

func TestAComponentStatingNoSourcePackageFoldsOnItsOwnName(t *testing.T) {
	// Coverage is producer-supplied and thin — none at all of 1,684 Go modules
	// and 3,880 generic components in that image — so a component that states
	// nothing is its own source package. Leaving it out of every grouping
	// would leave the majority ungrouped.
	one := described("pkg:golang/golang.org/x/net@0.38.0", "golang.org/x/net", "0.38.0", "", "")
	same := described("pkg:golang/golang.org/x/net@0.38.0", "golang.org/x/net", "0.38.0", "", "")
	moved := described("pkg:golang/golang.org/x/net@0.45.0", "golang.org/x/net", "0.45.0", "", "")

	if one.FoldKey() != same.FoldKey() {
		t.Error("one component described twice is two folds")
	}
	if one.FoldKey() == moved.FoldKey() {
		t.Error("two versions of one module folded together")
	}
}

func TestAFoldIsSpelledOneWayWhateverTheCapitals(t *testing.T) {
	// The same rule every other name people match on follows, and for the same
	// reason: the four engines do not fold alike outside ASCII, so the folding
	// happens here rather than being asked of one of them.
	lower := described("pkg:generic/openssl@3.5.1", "openssl", "3.5.1", "", "")
	upper := described("pkg:Generic/OpenSSL@3.5.1", "OpenSSL", "3.5.1", "", "")

	if lower.FoldKey() != upper.FoldKey() {
		t.Error("one component spelled with capitals is a second fold")
	}
}

func TestTheSourceVersionFallsBackToTheComponentsOwn(t *testing.T) {
	// A bare source package name is what a binary cut from a differently named
	// source usually carries — 459 of 535 in that image state the name alone.
	// It is not a lesser answer, and it must not leave the version half of the
	// key empty, or every such component would fold into one row.
	bare := described("pkg:deb/debian/bsdextrautils@2.41.5?distro=debian-13",
		"bsdextrautils", "2.41.5", "util-linux", "")
	other := described("pkg:deb/debian/mount@2.41.5?distro=debian-13",
		"mount", "2.41.5", "util-linux", "")
	later := described("pkg:deb/debian/mount@2.41.6?distro=debian-13",
		"mount", "2.41.6", "util-linux", "")

	if bare.FoldKey() != other.FoldKey() {
		t.Error("two binaries of one source at one version, neither stating a source version, are two folds")
	}
	if other.FoldKey() == later.FoldKey() {
		t.Error("two versions folded together because neither stated a source version")
	}
}

func TestTheFoldIsWrittenAsAComponentIsRecorded(t *testing.T) {
	// The key is computed once, on the way in, so that grouping is an indexed
	// column rather than an expression six queries each spell for themselves.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		components := graph.NewComponents(f.store.DB())

		siblings := []graph.Described{
			described("pkg:deb/debian/curl@8.14.1-2?distro=debian-13",
				"curl", "8.14.1-2", "curl", "8.14.1-2"),
			described("pkg:deb/debian/libcurl4t64@8.14.1-2?distro=debian-13",
				"libcurl4t64", "8.14.1-2", "curl", "8.14.1-2"),
		}
		moved := described("pkg:deb/debian/curl@8.15.0-1?distro=debian-13",
			"curl", "8.15.0-1", "curl", "8.15.0-1")

		if _, err := components.Intern(ctx, append(siblings, moved)); err != nil {
			t.Fatalf("record: %v", err)
		}

		var rows []graph.Component
		if err := f.store.DB().NewSelect().Model(&rows).
			Column("name", "version", "fold_key").Scan(ctx); err != nil {
			t.Fatalf("read back: %v", err)
		}
		// Keyed on both, because the same package at two versions is two rows
		// — which is the point being made.
		stored := map[string]string{}
		for _, row := range rows {
			if row.FoldKey == "" {
				t.Errorf("%s was recorded with no fold key", row.Name)
			}
			stored[row.Name+"@"+row.Version] = row.FoldKey
		}
		if len(stored) != 3 {
			t.Fatalf("recorded %d components, wanted 3: %v", len(stored), stored)
		}
		if stored["curl@8.14.1-2"] != stored["libcurl4t64@8.14.1-2"] {
			t.Error("two binaries of one source package were stored under two folds")
		}
		if stored["curl@8.14.1-2"] != siblings[0].FoldKey() {
			t.Error("the stored key is not the one the description computes")
		}
		if stored["curl@8.15.0-1"] != moved.FoldKey() {
			t.Error("the stored key is not the one the description computes")
		}
		if stored["curl@8.15.0-1"] == stored["curl@8.14.1-2"] {
			t.Error("a version bump left the fold where it was")
		}
	})
}

func TestALongNameOutsideASCIIStaysStorableAfterItIsCut(t *testing.T) {
	// A component name is a producer's text and the lookup key is bounded, so
	// the cut can fall inside a character. What is left is written to a column
	// on four engines: PostgreSQL refuses invalid UTF-8 outright and MySQL and
	// MariaDB refuse it in strict mode.
	name := strings.Repeat("é", 200)
	folded := graph.Folded(name)
	if !utf8.ValidString(folded) {
		t.Fatalf("the folded name is not valid UTF-8: %q", folded)
	}
	if !strings.HasPrefix(name, folded) {
		t.Error("the folded name is not a prefix of the name it folds")
	}
}
