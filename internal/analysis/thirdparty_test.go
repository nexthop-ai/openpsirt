// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/series"
)

// A declared third-party path is a prefix in its own right, as a repository
// is: every file under it shares it at any depth, the innermost of the
// repositories and the declared path holding a file wins, and a file under
// neither is learned for its directory.
func TestADeclaredThirdPartyPathIsThePrefixOfEveryFileUnderIt(t *testing.T) {
	run := &series.Run{Params: series.Params{ThirdParty: `["lib","src/vendor/zlib"]`}}
	modules := []series.Module{{Path: ""}, {Path: "lib/frr"}, {Path: "src/vendor/zlib/contrib"}}
	for _, c := range []struct {
		at, prefix string
		third      bool
	}{
		{"src/vendor/zlib/inflate.c", "src/vendor/zlib", true},
		{"src/vendor/zlib/doc/examples/zpipe.c", "src/vendor/zlib", true},
		{"src/vendor/zlib", "src/vendor/zlib", true},
		{"src/vendor/zlib/contrib/minizip/zip.c", "src/vendor/zlib/contrib", true},
		{"lib/frr/bgpd/bgp_route.c", "lib/frr", true},
		{"lib/other/a.c", "lib", true},
		{"src/vendor/zlibx/a.c", "src/vendor/zlibx", false},
		{"src/a.c", "src", false},
		{"a.c", "", false},
	} {
		declared := declaredThirdParty(run, c.at)
		if got := prefixOf(c.at, modules, declared); got != c.prefix {
			t.Errorf("%s is learned for %q; want %q", c.at, got, c.prefix)
		}
		if got := declared != ""; got != c.third {
			t.Errorf("%s is third-party: %v; want %v", c.at, got, c.third)
		}
	}
}

// A run that declared nothing, and a list that does not read as one, declare
// no file third-party.
func TestARunDeclaringNoThirdPartyPathDeclaresNoFile(t *testing.T) {
	for _, said := range []string{"", "null", "[]", "src/vendor", `{"src":true}`} {
		run := &series.Run{Params: series.Params{ThirdParty: said}}
		if got := declaredThirdParty(run, "src/vendor/a.c"); got != "" {
			t.Errorf("a run declaring %q declares src/vendor/a.c under %q", said, got)
		}
	}
}
