// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

func TestOnlyControlCharactersAreDroppedFromAName(t *testing.T) {
	for _, each := range []struct{ in, want string }{
		{"curl", "curl"},
		{"curl\u001e1", "curl1"},
		{"a\x00b\x1fc\x7f", "abc"},
		{"tab\tand\nline", "tabandline"},
		{"next\u0085line", "nextline"},
		{"漢字\x01", "漢字"},
		{"bad\xffbyte\x02", "bad\xffbyte"},
		{"", ""},
	} {
		if got := graph.Printable(each.in); got != each.want {
			t.Errorf("Printable(%q) = %q, want %q", each.in, got, each.want)
		}
	}
}

func TestAnEscapedControlCharacterIsNotPartOfAPackageIdentifier(t *testing.T) {
	// Decoded, the escape stands in for the separator a key joins its parts
	// with, so two different version pairs could join to one key.
	if _, version := graph.PackageOf("pkg:deb/debian/curl@a%00b"); version != "ab" {
		t.Errorf("the version decoded as %q", version)
	}
	if name, version := graph.UpstreamFromPurl("pkg:deb/debian/libcurl4@8?upstream=curl%1E%40a%00b"); name != "curl" || version != "ab" {
		t.Errorf("the upstream decoded as %q at %q", name, version)
	}
	if parts := graph.PartsOfPurl("pkg:maven/org%1Eexample/lib@1"); parts.Namespace != "orgexample" {
		t.Errorf("the namespace decoded as %q", parts.Namespace)
	}
}
