// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package patchbranch

import (
	"net/url"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// CommitLink is the page showing a commit in a repository, where the
// repository is on a host whose page for a commit has a known shape.
//
// Answers false for any other host, and for an address or a hash of no
// recognized shape. A vulnerability record names a repository by its clone
// address and a commit by its hash, and only a host's own convention turns the
// two into a page; a guessed shape on an unknown host is a link to nothing, or
// to somewhere else. Every link made here reads back through Parse as the same
// repository and commit, so it is labeled with branches like any patch link.
//
// The shapes made:
//
//	github.com      https://github.com/{owner}/{repo}/commit/{hash}
//	gitlab.com      https://gitlab.com/{group…}/{repo}/-/commit/{hash}
//	git.kernel.org  https://git.kernel.org/stable/c/{hash}, /linus/{hash} for
//	                the stable and mainline trees, and
//	                https://git.kernel.org/pub/scm/{path…}/commit/?id={hash}
func CommitLink(repository, hash string) (string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(repository))
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" ||
		parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if !outward.HostName(host) {
		return "", false
	}
	hash = strings.ToLower(strings.TrimSpace(hash))
	if !hexName.MatchString(hash) {
		return "", false
	}
	parts := strings.Split(strings.TrimSuffix(strings.Trim(parsed.Path, "/"), ".git"), "/")
	for _, part := range parts {
		// A lone dash is GitLab's marker between a repository and what is in
		// it, so it is never part of a repository's path.
		if !segment.MatchString(part) || part == "." || part == ".." || part == "-" {
			return "", false
		}
	}
	path := strings.Join(parts, "/")
	switch host {
	case "github.com":
		if len(parts) != 2 {
			return "", false
		}
		return "https://github.com/" + path + "/commit/" + hash, true
	case "gitlab.com":
		if len(parts) < 2 {
			return "", false
		}
		return "https://gitlab.com/" + path + "/-/commit/" + hash, true
	case "git.kernel.org":
		if len(parts) < 3 || parts[0] != "pub" || parts[1] != "scm" {
			return "", false
		}
		whole := "https://git.kernel.org/" + path + ".git"
		for short, tree := range map[string]string{"stable/c/": kernelShort["stable"], "linus/": kernelShort["linus"]} {
			if whole == tree {
				return "https://git.kernel.org/" + short + hash, true
			}
		}
		return whole + "/commit/?id=" + hash, true
	default:
		return "", false
	}
}
