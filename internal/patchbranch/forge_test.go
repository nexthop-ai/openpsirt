// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
)

// A repository and commit from a vulnerability record become a page on the
// hosts whose commit page has a known shape, and the page reads back as the
// same repository and commit, so it takes branch labels.
func TestACommitLinkIsMadeOnKnownHostsAndReadsBack(t *testing.T) {
	const curl = "c3c70440e8d9938c0bb732595751e8aebc614f24"
	for _, each := range []struct {
		repository, hash, link, reads string
	}{
		{"https://github.com/curl/curl.git", curl,
			"https://github.com/curl/curl/commit/" + curl, "https://github.com/curl/curl.git"},
		{"https://github.com/Curl/Curl", "C3C70440E8D9938C0BB732595751E8ABC614F24"[:7],
			"https://github.com/Curl/Curl/commit/c3c7044", "https://github.com/curl/curl.git"},
		{"http://github.com/curl/curl/", curl,
			"https://github.com/curl/curl/commit/" + curl, "https://github.com/curl/curl.git"},
		{"https://gitlab.com/gnutls/gnutls.git", full,
			"https://gitlab.com/gnutls/gnutls/-/commit/" + full, "https://gitlab.com/gnutls/gnutls.git"},
		{"https://gitlab.com/group/sub/project", full,
			"https://gitlab.com/group/sub/project/-/commit/" + full, "https://gitlab.com/group/sub/project.git"},
		{"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git", full,
			"https://git.kernel.org/stable/c/" + full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"},
		{"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux", full,
			"https://git.kernel.org/linus/" + full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"},
		{"https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git", full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git/commit/?id=" + full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git"},
	} {
		link, ok := patchbranch.CommitLink(each.repository, each.hash)
		if !ok || link != each.link {
			t.Errorf("%s at %s made %q (%v), want %q", each.repository, each.hash, link, ok, each.link)
			continue
		}
		commit, ok := patchbranch.Parse(link)
		if !ok || commit.Repository != each.reads {
			t.Errorf("%s reads back as %+v (%v), want repository %s", link, commit, ok, each.reads)
		}
	}
}

// No link is made for a host with no known commit page, nor from an address or
// hash a record could use to point somewhere else.
func TestACommitLinkIsRefusedOutsideTheKnownShapes(t *testing.T) {
	for _, each := range []struct{ repository, hash string }{
		{"https://go.googlesource.com/net", full},
		{"https://bitbucket.org/owner/repo.git", full},
		{"https://github.com.evil.test/curl/curl", full},
		{"https://evil.test/github.com/curl/curl", full},
		{"git://github.com/curl/curl.git", full},
		{"javascript:alert(1)//github.com/a/b", full},
		{"ssh://git@github.com/curl/curl.git", full},
		{"https://user@github.com/curl/curl", full},
		{"https://github.com:8443/curl/curl", full},
		{"https://github.com/curl/curl?x=1", full},
		{"https://github.com/curl/curl#frag", full},
		{"https://github.com/curl", full},
		{"https://github.com/curl/curl/tree", full},
		{"https://github.com/../curl", full},
		{"https://github.com/curl/c url", full},
		{"https://gitlab.com/group/-/project", full},
		{"https://git.kernel.org/cgit/linux.git", full},
		{"https://github.com/curl/curl", "v8.14.1"},
		{"https://github.com/curl/curl", "123456"},
		{"https://github.com/curl/curl", full + "/../x"},
	} {
		if link, ok := patchbranch.CommitLink(each.repository, each.hash); ok {
			t.Errorf("%s at %s made %q, want no link", each.repository, each.hash, link)
		}
	}
}
