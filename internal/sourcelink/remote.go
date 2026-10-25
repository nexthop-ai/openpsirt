// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sourcelink

import (
	"net/url"
	"strings"
)

// Normalize is a repository's address as host, owner and name, in lower
// case, with no scheme, credential, port, revision or suffix: the form a
// remote and a package identifier are compared in. Empty where the address
// names no repository.
func Normalize(remote string) string {
	host, path := parse(remote)
	if host == "" || path == "" {
		return ""
	}
	return strings.ToLower(host + "/" + path)
}

// parse is a remote's host and repository path, the path in the case it was
// written in. A hosting service matches owners and names in any case, and a
// link written as the remote spells it reads as the repository does.
func parse(remote string) (host, path string) {
	s := strings.TrimSpace(remote)
	s, _, _ = strings.Cut(s, "#")
	s, _, _ = strings.Cut(s, "?")
	if len(s) >= 4 && strings.EqualFold(s[:4], "git+") {
		s = s[4:]
	}
	if at := strings.Index(s, "://"); at >= 0 {
		s = s[at+3:]
	} else if at := strings.Index(s, "@"); at >= 0 && strings.Contains(s[at:], ":") {
		// The form an SSH remote is written in: user@host:owner/name.
		s = strings.Replace(s[at+1:], ":", "/", 1)
	} else if h, after, ok := strings.Cut(s, ":"); ok && !strings.Contains(h, "/") && len(h) > 1 && !strings.HasPrefix(after, "//") {
		// The form an SSH remote with no user is written in: host:owner/name.
		// A single letter before the colon is a drive.
		s = h + "/" + after
	}
	host, path, _ = strings.Cut(s, "/")
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	host, _, _ = strings.Cut(host, ":")
	// A revision follows the path, as a version-control address in a package
	// identifier writes it.
	path, _, _ = strings.Cut(path, "@")
	path = strings.TrimSuffix(path, "/")
	if strings.HasSuffix(strings.ToLower(path), ".git") {
		path = path[:len(path)-4]
	}
	return strings.ToLower(host), path
}

// WithoutCredential is a remote with any credential and query taken out of
// it, where it is written as an address. A remote comes from an upload, and a
// token in it would reach every reader of what it is shown on.
func WithoutCredential(remote string) string {
	s := strings.TrimSpace(remote)
	if !strings.Contains(s, "://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil {
		// An address that does not parse is not shown, since where its
		// credential ends cannot be told.
		return ""
	}
	u.User, u.RawQuery, u.ForceQuery = nil, "", false
	return u.String()
}

// relative is whether a remote is written relative to the repository that
// holds it, as a submodule's often is.
func relative(remote string) bool {
	s := strings.TrimSpace(remote)
	return strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
}

// resolve is a relative remote read against the remote of the repository
// holding it: each leading ".." climbs one segment of the parent's path.
func resolve(parent, remote string) string {
	host, path := parse(parent)
	if host == "" {
		return ""
	}
	segments := strings.Split(path, "/")
	for _, part := range strings.Split(strings.TrimSpace(remote), "/") {
		switch part {
		case ".", "":
		case "..":
			if len(segments) == 0 {
				return ""
			}
			segments = segments[:len(segments)-1]
		default:
			segments = append(segments, part)
		}
	}
	if len(segments) == 0 {
		return ""
	}
	return host + "/" + strings.Join(segments, "/")
}
