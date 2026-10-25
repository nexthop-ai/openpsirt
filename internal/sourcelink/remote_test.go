// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sourcelink

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
		if got := Normalize(remote); got != "github.com/frrouting/frr" {
			t.Errorf("%q is %q; want github.com/frrouting/frr", remote, got)
		}
	}
	for _, remote := range []string{"", "github.com", "https://"} {
		if got := Normalize(remote); got != "" {
			t.Errorf("%q is %q; want nothing, since it names no repository", remote, got)
		}
	}
}

func TestARelativeRemoteIsReadAgainstTheRepositoryHoldingIt(t *testing.T) {
	for _, c := range []struct{ parent, remote, want string }{
		{"https://github.com/sonic-net/sonic-buildimage", "../sonic-swss.git", "github.com/sonic-net/sonic-swss"},
		{"git@github.com:sonic-net/sonic-buildimage.git", "./vendored", "github.com/sonic-net/sonic-buildimage/vendored"},
		{"https://github.com/sonic-net/sonic-buildimage", "../../../x", ""},
		{"", "../sonic-swss", ""},
	} {
		if got := Normalize(resolve(c.parent, c.remote)); got != c.want {
			t.Errorf("%q against %q is %q; want %q", c.remote, c.parent, got, c.want)
		}
	}
}
