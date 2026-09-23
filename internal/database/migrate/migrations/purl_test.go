// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The upgrade reads the version a statement is about as the graph reads it for
// a statement uploaded today, and carries its own copy of that reading.
func TestTheUpgradeReadsAPackageVersionAsTheGraphDoes(t *testing.T) {
	for _, purl := range []string{
		"pkg:deb/debian/openssl@3.0.11-1%2Bdeb12u2?arch=amd64",
		"pkg:npm/%40scope/name@1.2.3#sub/path",
		"PKG:golang/example.com/a/b@v1.0.0",
		"pkg:generic/zlib",
		"pkg:generic@1.0",
		"pkg:maven/org.example/lib@1.0%ZZ",
		"http://example.com/a@1",
		"",
	} {
		if got, want := purlVersion(purl), graph.PartsOfPurl(purl).Version; got != want {
			t.Errorf("%q: the upgrade reads %q and the graph %q", purl, got, want)
		}
	}
}
