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
// it. A remote comes from an upload, and a token in it would reach every
// reader of what it is shown on. One whose credential cannot be told apart
// from the rest is not shown.
func WithoutCredential(remote string) string {
	s := strings.TrimSpace(remote)
	if !Schemed(s) {
		bare, readable := WithoutPassword(s)
		if !readable {
			return ""
		}
		bare, _, _ = strings.Cut(bare, "?")
		return bare
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

// Schemed is whether an address opens on a scheme and "://", or on "//"
// naming a host with no scheme. Either is read as an address with a user,
// host, query and fragment; anything else, a "://" later in a path included,
// is read as written without a scheme.
func Schemed(address string) bool {
	if strings.HasPrefix(address, "//") {
		return true
	}
	end := strings.Index(address, "://")
	if end <= 0 {
		return false
	}
	for i, c := range address[:end] {
		letter := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
		later := ('0' <= c && c <= '9') || c == '+' || c == '-' || c == '.'
		if !letter && (i == 0 || !later) {
			return false
		}
	}
	return true
}

// WithoutPassword is an address written without a scheme, such as a purl's
// `repository_url` or an scp-style remote, with a user and password written
// before its host taken out, and whether it can be read at all.
//
// A user with no password is kept: it is the account an scp-style address
// such as `git@host:path` names. A colon before the first slash with no `@`
// there, and an `@` after it, is a password holding a slash or a path holding
// an `@`; the two cannot be told apart, so it cannot be read.
func WithoutPassword(address string) (string, bool) {
	head := address
	if end := strings.IndexAny(head, "?#"); end >= 0 {
		head = head[:end]
	}
	host := head
	if end := strings.IndexByte(host, '/'); end >= 0 {
		host = host[:end]
	}
	if at := strings.LastIndex(host, "@"); at >= 0 {
		if at > 0 && at < len(host)-1 && strings.Contains(host[:at], ":") {
			return address[at+1:], true
		}
		return address, true
	}
	if strings.Contains(host, ":") && strings.Contains(head[len(host):], "@") {
		return "", false
	}
	return address, true
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
