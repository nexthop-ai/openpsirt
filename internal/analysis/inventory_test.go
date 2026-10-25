// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import "testing"

func TestAPackageIdentifierNamesTheRepositoryItWasBuiltFrom(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:github/FRRouting/frr@10.2":  "github.com/frrouting/frr",
		"pkg:gitlab/group/sub/project@1": "gitlab.com/group/sub/project",
		"pkg:bitbucket/team/repo":        "bitbucket.org/team/repo",
		"pkg:generic/frr@10.2?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2FFRRouting%2Ffrr.git%40def": "github.com/frrouting/frr",
		"pkg:deb/debian/frr@10.2": "",
		"pkg:github/frr@10.2":     "",
	} {
		if got := remoteOfPurl(purl); got != want {
			t.Errorf("%q names %q; want %q", purl, got, want)
		}
	}
}
