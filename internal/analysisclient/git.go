// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysisclient

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"path"
	"sort"
	"strings"
)

// git runs the git command in a directory, returning what it printed.
type git func(ctx context.Context, dir string, args ...string) (string, error)

// runGit is git as installed on the build host.
func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...) //nolint:gosec // G204: a fixed program, with arguments this package writes
	var out, errs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errs
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errs.String()))
	}
	return out.String(), nil
}

// repository is one repository the checkout holds: the checkout itself, at
// the empty path, or a submodule at any depth.
type repository struct {
	// Path is where it sits, relative to the top of the checkout.
	Path string
	// Remote is its web address, empty where it has none.
	Remote string
	// Commit is the commit its working tree was at.
	Commit string
	// Changed is whether its tracked files differed from that commit.
	Changed bool
}

// indexed is every path the git index of the checkout holds, the submodules'
// included, in the case the index holds it in.
func indexed(ctx context.Context, run git, root string) ([]string, error) {
	out, err := run(ctx, root, "ls-files", "--recurse-submodules", "-z")
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// repositories is the checkout and every submodule checked out in it, at any
// depth, each with its web address, its commit and whether it was changed.
// commit is the checkout's commit where the pipeline states it.
func repositories(ctx context.Context, run git, root, commit string) ([]repository, error) {
	top := repository{Commit: commit}
	if top.Commit == "" {
		head, err := run(ctx, root, "rev-parse", "HEAD")
		if err != nil {
			return nil, err
		}
		top.Commit = strings.TrimSpace(head)
	}
	raw := map[string]string{}
	if remote, err := run(ctx, root, "remote", "get-url", "origin"); err == nil {
		raw[""] = strings.TrimSpace(remote)
	}
	changed, err := dirty(ctx, run, root)
	if err != nil {
		return nil, err
	}
	top.Changed = changed
	out := []repository{top}

	status, err := run(ctx, root, "submodule", "status", "--recursive")
	if err != nil {
		return nil, err
	}
	var subs []repository
	for _, line := range strings.Split(status, "\n") {
		if len(line) < 2 {
			continue
		}
		// A leading minus is a submodule that was never checked out, so
		// nothing in it was analyzed.
		if line[0] == '-' {
			continue
		}
		// The commit, the path, and what the commit describes as in
		// parentheses where it describes as anything. A path may hold a
		// space.
		sha, p, ok := strings.Cut(line[1:], " ")
		if !ok || p == "" {
			continue
		}
		if i := strings.LastIndex(p, " ("); i >= 0 && strings.HasSuffix(p, ")") {
			p = p[:i]
		}
		subs = append(subs, repository{Path: p, Commit: sha})
	}
	// A parent is read before what it holds, so a relative address resolves
	// against an address already known.
	sort.Slice(subs, func(i, j int) bool { return subs[i].Path < subs[j].Path })
	declared := map[string]map[string]string{}
	for i := range subs {
		s := &subs[i]
		parent := parentOf(s.Path, subs[:i])
		urls, ok := declared[parent]
		if !ok {
			urls = declaredURLs(ctx, run, root, parent)
			declared[parent] = urls
		}
		within := strings.TrimPrefix(strings.TrimPrefix(s.Path, parent), "/")
		address := urls[within]
		if relative(address) {
			address = resolveRelative(raw[parent], address)
		}
		raw[s.Path] = address
		changed, err := dirty(ctx, run, root+"/"+s.Path)
		if err != nil {
			return nil, err
		}
		s.Changed = changed
	}
	out = append(out, subs...)
	for i := range out {
		out[i].Remote = webAddress(raw[out[i].Path])
	}
	return out, nil
}

// parentOf is the deepest repository already listed holding a path, and the
// checkout where none does.
func parentOf(p string, known []repository) string {
	best := ""
	for _, k := range known {
		if strings.HasPrefix(p, k.Path+"/") && len(k.Path) > len(best) {
			best = k.Path
		}
	}
	return best
}

// declaredURLs is the address each submodule a repository declares is
// cloned from, by its path in that repository.
func declaredURLs(ctx context.Context, run git, root, repo string) map[string]string {
	dir := root
	if repo != "" {
		dir = root + "/" + repo
	}
	// Each entry as its key, a line feed and its value, ended by a NUL: a
	// submodule's name and path may hold a space.
	out, err := run(ctx, dir, "config", "--null", "--file", ".gitmodules", "--get-regexp", `^submodule\..*\.(path|url)$`)
	if err != nil {
		return nil
	}
	paths, urls := map[string]string{}, map[string]string{}
	for _, entry := range strings.Split(out, "\x00") {
		key, value, ok := strings.Cut(entry, "\n")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch {
		case strings.HasSuffix(key, ".path"):
			paths[strings.TrimSuffix(key, ".path")] = value
		case strings.HasSuffix(key, ".url"):
			urls[strings.TrimSuffix(key, ".url")] = value
		}
	}
	byPath := map[string]string{}
	for name, p := range paths {
		byPath[strings.Trim(p, "/")] = urls[name]
	}
	return byPath
}

// dirty is whether a working tree's tracked files differ from its commit.
// Files the build wrote that git does not track are not a change.
func dirty(ctx context.Context, run git, dir string) (bool, error) {
	out, err := run(ctx, dir, "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=all")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

func relative(address string) bool {
	return strings.HasPrefix(address, "./") || strings.HasPrefix(address, "../")
}

// resolveRelative is a submodule address written relative to its parent's,
// resolved as git resolves it: each leading "../" takes one segment off the
// parent's address.
func resolveRelative(parent, address string) string {
	if parent == "" {
		return ""
	}
	base := strings.TrimSuffix(parent, "/")
	for {
		switch {
		case strings.HasPrefix(address, "./"):
			address = address[2:]
		case strings.HasPrefix(address, "../"):
			address = address[3:]
			cut := strings.LastIndexAny(base, "/:")
			if cut < 0 {
				return ""
			}
			base = base[:cut]
		default:
			return base + "/" + address
		}
	}
}

// webAddress is a repository's address as a web address: HTTPS, with no
// credential, port, query or ".git". An SSH address becomes the web address
// of the same repository. A local path has none.
func webAddress(address string) string {
	s := strings.TrimSpace(address)
	if s == "" {
		return ""
	}
	var host, p string
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		switch strings.ToLower(u.Scheme) {
		case "https", "http", "ssh", "git", "git+ssh", "ssh+git":
		default:
			return ""
		}
		host, p = u.Hostname(), u.Path
	} else if at := strings.Index(s, "@"); at >= 0 && strings.Contains(s[at:], ":") && !strings.Contains(s[:at], "/") {
		// user@host:owner/name, the form SSH addresses are written in.
		rest := s[at+1:]
		h, after, _ := strings.Cut(rest, ":")
		host, p = h, "/"+after
	} else if h, after, ok := strings.Cut(s, ":"); ok && !strings.Contains(h, "/") && len(h) > 1 && !strings.HasPrefix(after, "//") {
		// host:owner/name, with no user.
		host, p = h, "/"+after
	} else {
		return ""
	}
	p = path.Clean("/" + strings.TrimPrefix(p, "/"))
	p = strings.TrimSuffix(p, ".git")
	if host == "" || p == "/" || p == "." {
		return ""
	}
	return "https://" + strings.ToLower(host) + p
}
