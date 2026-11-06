// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestAPurlPrefixMatchesOnePackageOrAPathWithTheVersionAndQualifiersCut(t *testing.T) {
	cases := []struct {
		prefix, purl string
		want         bool
	}{
		{"pkg:github/sonic-net/sonic-swss", "pkg:github/sonic-net/sonic-swss@2126d2752826", true},
		{"pkg:github/sonic-net/sonic-swss", "pkg:github/sonic-net/sonic-swss-common@1a2b", false},
		// A package is not a path: what sits under it is a package of its own.
		{"pkg:golang/go.opentelemetry.io/otel", "pkg:golang/go.opentelemetry.io/otel/trace@v1.2.0", false},
		{"pkg:golang/go.opentelemetry.io/otel/", "pkg:golang/go.opentelemetry.io/otel/trace@v1.2.0", true},
		{"pkg:github/sonic-net/", "pkg:github/sonic-net/sonic-swss-common@1a2b", true},
		{"pkg:github/sonic-net/", "pkg:github/sonic-netx/thing@1", false},
		{"pkg:golang/github.com/sonic-net/", "pkg:golang/github.com/sonic-net/sonic-gnmi@v0.1.0", true},
		// The qualifiers and the version a typed prefix carries are cut too.
		{"pkg:deb/debian/curl@8.1?arch=amd64", "pkg:deb/debian/curl@7.0?distro=debian-12", true},
		// Capitals are ignored on both sides, and an escape reads as what it spells.
		{"PKG:GitHub/Sonic-Net/", "pkg:github/sonic-net/sonic-swss@1", true},
		{"pkg:npm/@babel/core", "pkg:npm/%40babel/core@7.0.0", true},
		// A component with no identifier and a prefix naming no package match nothing.
		{"pkg:github/sonic-net/", "", false},
		{"sonic-swss", "pkg:github/sonic-net/sonic-swss@1", false},
		{"pkg:", "pkg:github/sonic-net/sonic-swss@1", false},
	}
	for _, c := range cases {
		if got := graph.ParsePurlPrefix(c.prefix).Matches(c.purl); got != c.want {
			t.Errorf("%q against %q: got %v, want %v", c.prefix, c.purl, got, c.want)
		}
	}
}
