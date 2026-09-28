// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestWhatTheScannerCannotMatchIsNamedWithTheReason(t *testing.T) {
	// Each row is a shape the scanner was run over with one component per
	// inventory, and the reason is what it answered nothing for.
	const cpe = "cpe:2.3:a:openssl:openssl:1.1.1a:*:*:*:*:*:*:*"
	for _, c := range []struct {
		purl, cpe, version string
		want               graph.Unmatchable
	}{
		// Matched.
		{"pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", "", "3.0.11-1", ""},
		{"pkg:deb/debian/openssl@3.0.11-1?os_name=debian&os_version=12", "", "3.0.11-1", ""},
		{"pkg:apk/alpine/openssl@3.1.0-r0?distro=alpine-3.18.0", "", "3.1.0-r0", ""},
		{"pkg:generic/openssl@1.1.1a", cpe, "1.1.1a", ""},
		{"pkg:golang/golang.org/x/net@v0.7.0", "", "v0.7.0", ""},
		{"pkg:pypi/requests@2.19.0", "", "2.19.0", ""},
		{"pkg:cargo/openssl@0.10.55", "", "0.10.55", ""},
		{"pkg:npm/lodash@4.17.15", "", "4.17.15", ""},

		{"", "", "1.1.1a", graph.NoIdentifier},
		{"", cpe, "1.1.1a", graph.NoIdentifier},
		{"https://example.com/openssl", "", "1.1.1a", graph.NoIdentifier},
		{"pkg:oci/docker-database@latest", "", "latest", graph.UnpublishedKind},
		{"pkg:github/sonic-net/sonic-swss@abcdef123456", "", "abcdef123456", graph.UnpublishedKind},
		{"pkg:generic/openssl@UNKNOWN", cpe, "UNKNOWN", graph.NoVersion},
		{"pkg:generic/openssl", cpe, "", graph.NoVersion},
		{"pkg:golang/golang.org/x/net@(devel)", "", "(devel)", graph.NoVersion},
		{"pkg:pypi/requests", "", " ", graph.NoVersion},
		// No version comes before no distribution: either alone is enough.
		{"pkg:deb/debian/openssl", "", "", graph.NoVersion},
		{"pkg:deb/debian/openssl@3.0.11-1", "", "3.0.11-1", graph.NoDistribution},
		{"pkg:deb/debian/openssl@3.0.11-1", cpe, "3.0.11-1", graph.NoDistribution},
		{"pkg:deb/sonic/linux-image@6.12.41-1?arch=amd64", "", "6.12.41-1", graph.NoDistribution},
		{"pkg:rpm/redhat/openssl@1.1.1k-1.el8", "", "1.1.1k-1.el8", graph.NoDistribution},
		{"pkg:apk/alpine/openssl@3.1.0-r0?os_name=alpine", "", "3.1.0-r0", graph.NoDistribution},
		{"pkg:generic/openssl@1.1.1a", "", "1.1.1a", graph.GenericWithoutCPE},
	} {
		d := graph.Described{Purl: c.purl, CPE: c.cpe, Name: "x", Version: c.version}
		if got := d.Unmatchable(); got != c.want {
			t.Errorf("%q (cpe %t, version %q) is %q, want %q", c.purl, c.cpe != "", c.version, got, c.want)
		}
	}
}

func TestABuildListsWhatNothingCanMatchByReason(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		held := []graph.Described{
			{Purl: "pkg:deb/debian/zlib@1.3?distro=debian-13", Name: "zlib", Version: "1.3"},
			{Purl: "pkg:deb/sonic/linux-image@6.12.41-1?arch=amd64", Name: "linux-image", Version: "6.12.41-1"},
			{Purl: "pkg:generic/8250_exar@UNKNOWN", Name: "8250_exar", Version: "UNKNOWN",
				CPE: "cpe:2.3:a:8250_exar:8250_exar:UNKNOWN:*:*:*:*:*:*:*"},
			{Name: "Bash", Version: "5.2"},
			{Name: "awk", Version: "1"},
		}
		snap := graph.Snapshot{Root: root, Components: held}
		for _, d := range held {
			snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: d})
		}
		if _, err := f.store.Apply(ctx, f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		listed, total, err := f.store.Unmatched(ctx, everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if total != len(held) {
			t.Errorf("the build holds %d, want %d", total, len(held))
		}
		// By reason in the order they are tested, then by name without regard
		// to capitals.
		want := []struct {
			name   string
			reason graph.Unmatchable
		}{
			{"awk", graph.NoIdentifier}, {"Bash", graph.NoIdentifier},
			{"8250_exar", graph.NoVersion}, {"linux-image", graph.NoDistribution},
		}
		if len(listed) != len(want) {
			t.Fatalf("listed %+v, want %v", listed, want)
		}
		for i, w := range want {
			if listed[i].Name != w.name || listed[i].Reason != w.reason {
				t.Errorf("row %d is %s (%s), want %s (%s)", i, listed[i].Name, listed[i].Reason, w.name, w.reason)
			}
		}
	})
}
