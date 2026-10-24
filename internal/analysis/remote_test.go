// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import "testing"

func TestEveryWayOfWritingARepositoryNamesTheSameOne(t *testing.T) {
	for _, remote := range []string{
		"https://github.com/FRRouting/frr",
		"https://github.com/FRRouting/frr.git",
		"https://github.com/FRRouting/frr/",
		"git+https://github.com/FRRouting/frr.git@def0123",
		"https://token:x-oauth@github.com/FRRouting/frr.git",
		"ssh://git@github.com:22/FRRouting/frr.git",
		"git@github.com:FRRouting/frr.git",
		"https://github.com/FRRouting/frr.git#readme",
	} {
		if got := normalizedRemote(remote); got != "github.com/frrouting/frr" {
			t.Errorf("%q is %q; want github.com/frrouting/frr", remote, got)
		}
	}
	for _, remote := range []string{"", "github.com", "https://"} {
		if got := normalizedRemote(remote); got != "" {
			t.Errorf("%q is %q; want nothing, since it names no repository", remote, got)
		}
	}
}

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
