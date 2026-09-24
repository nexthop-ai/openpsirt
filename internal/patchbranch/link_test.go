// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
)

const (
	full  = "3439c15ae91a517cf3c650ea15a8987699416ad9"
	short = "3439c15"
)

func TestALinkNamingACommitIsReadAsItsRepositoryAndHash(t *testing.T) {
	for _, each := range []struct {
		link       string
		repository string
		hash       string
	}{
		{"https://git.kernel.org/stable/c/" + full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git", full},
		{"https://git.kernel.org/linus/" + full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git", full},
		{"https://git.kernel.org/linus/c/" + full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git", full},
		{"https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=" + full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git", full},
		{"https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git/commit/?id=" + full,
			"https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git", full},
		{"https://cgit.git.savannah.gnu.org/cgit/gzip.git/commit/?id=" + full,
			"https://https.git.savannah.gnu.org/git/gzip.git", full},
		{"https://git.savannah.gnu.org/cgit/coreutils.git/commit/?id=" + full,
			"https://https.git.savannah.gnu.org/git/coreutils.git", full},
		{"https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/?id=" + full,
			"https://https.git.savannah.nongnu.org/git/acl.git", full},
		{"https://git.savannah.nongnu.org/cgit/attr.git/commit/?id=" + full,
			"https://https.git.savannah.nongnu.org/git/attr.git", full},
		{"https://cgit.freebsd.org/ports/commit/?id=" + full,
			"https://git.freebsd.org/ports.git", full},
		{"https://cgit.freebsd.org/ports.git/commit/?id=" + full,
			"https://git.freebsd.org/ports.git", full},
		{"https://github.com/madler/zlib/commit/" + full,
			"https://github.com/madler/zlib.git", full},
		{"https://github.com/madler/zlib/commit/" + full + ".patch",
			"https://github.com/madler/zlib.git", full},
		{"https://github.com/madler/zlib/commit/" + short + "#diff-1",
			"https://github.com/madler/zlib.git", short},
		{"https://github.com/madler/zlib/pull/41/commits/" + full,
			"https://github.com/madler/zlib.git", full},
		{"https://gitlab.com/gnuwget/wget/-/commit/" + full,
			"https://gitlab.com/gnuwget/wget.git", full},
		{"https://gitlab.gnome.org/GNOME/libxml2/-/commit/" + full,
			"https://gitlab.gnome.org/GNOME/libxml2.git", full},
		{"http://GitHub.com/madler/zlib/commit/" + "3439C15AE91A517CF3C650EA15A8987699416AD9",
			"https://github.com/madler/zlib.git", full},
	} {
		got, ok := patchbranch.Parse(each.link)
		if !ok {
			t.Errorf("%s was not read as a commit", each.link)
			continue
		}
		if got.Repository != each.repository || got.Hash != each.hash {
			t.Errorf("%s was read as %s at %s, want %s at %s",
				each.link, got.Hash, got.Repository, each.hash, each.repository)
		}
	}
}

func TestALinkNamingNoOneCommitNamesNoRepository(t *testing.T) {
	for _, link := range []string{
		// A fix described, and nowhere it landed.
		"https://github.com/madler/zlib/pull/41",
		"https://gitlab.gnome.org/GNOME/libxml2/-/merge_requests/12",
		"https://patchwork.kernel.org/patch/" + full + "/",
		"https://lists.debian.org/debian-lts-announce/2025/10/msg00008.html",
		"https://github.com/the-tcpdump-group/tcpdump/commits/master/print-hncp.c",
		// A commit name too short to be one, or not one at all.
		"https://github.com/madler/zlib/commit/abc12",
		"https://github.com/madler/zlib/commit/zzzzzzzz",
		"https://git.busybox.net/busybox/commit/archival?id=" + full,
		// An address carrying what git would read as more than a repository.
		"https://user:secret@github.com/madler/zlib/commit/" + full,
		"https://github.com:8443/madler/zlib/commit/" + full,
		"https://github.com/madler/../zlib/commit/" + full,
		"https://github.com/mad%20ler/zlib/commit/" + full,
		"ftp://github.com/madler/zlib/commit/" + full,
		"https://github.com/commit/" + full,
		"not an address",
	} {
		if got, ok := patchbranch.Parse(link); ok {
			t.Errorf("%s was read as %s at %s, want no commit", link, got.Hash, got.Repository)
		}
	}
}

func TestBranchesAreListedInTheOrderTheirVersionsRun(t *testing.T) {
	for _, each := range []struct{ before, after string }{
		{"linux-6.6.y", "linux-6.12.y"},
		{"linux-6.12.y", "linux-7.0.y"},
		{"linux-5.15.y", "linux-6.1.y"},
		{"linux-6.1.y", "linux-rolling-lts"},
		{"release-2", "release-10"},
		{"linux-6.1.y", "linux-6.1.y-rc"},
	} {
		if !patchbranch.VersionLess(each.before, each.after) {
			t.Errorf("%s is not listed before %s", each.before, each.after)
		}
		if patchbranch.VersionLess(each.after, each.before) {
			t.Errorf("%s is listed before %s", each.after, each.before)
		}
	}
}
