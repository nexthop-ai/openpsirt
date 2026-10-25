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
		"github.com:FRRouting/frr.git",
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

func TestACredentialIsTakenOutOfARemote(t *testing.T) {
	for remote, want := range map[string]string{ //nolint:gosec // G101: example remotes carrying placeholder credentials to be removed
		"https://gitlab-ci-token:SECRET@gitlab.example.com/g/p.git": "https://gitlab.example.com/g/p.git",
		"git+https://SECRET@github.com/a/b.git":                     "git+https://github.com/a/b.git",
		"https://github.com/a/b.git?access_token=SECRET":            "https://github.com/a/b.git",
		"https://github.com/a/b.git":                                "https://github.com/a/b.git",
		"git@github.com:a/b.git":                                    "git@github.com:a/b.git",
		"../sibling.git":                                            "../sibling.git",
		"https://SECRET@[::1/x":                                     "",
	} {
		if got := WithoutCredential(remote); got != want {
			t.Errorf("%q is %q; want %q", remote, got, want)
		}
	}
}

func TestAnSSHRemoteWithNoUserNamesItsRepository(t *testing.T) {
	if got := Normalize("github.com:sonic-net/sonic-swss.git"); got != "github.com/sonic-net/sonic-swss" {
		t.Errorf("named %q", got)
	}
}
