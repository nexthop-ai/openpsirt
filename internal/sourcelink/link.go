// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sourcelink

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Module is a repository a run's checkout held: where it sits in the
// checkout, its remote as the run stated it, the commit it was pinned to,
// and whether its working tree differed from that commit.
type Module struct {
	Path     string
	Remote   string
	Revision string
	Changed  bool
}

// Link is where a location opens, or why it opens nowhere.
type Link struct {
	// URL is the address, empty where the location is shown unlinked.
	URL string
	// Repository is the repository the location is in: its web address
	// where it is on a host the product names, the remote as stated with no
	// credential otherwise.
	Repository string
	// Within is the location's path inside that repository.
	Within string
	// Revision is the commit the link opens at, or the branch of an
	// approximate one.
	Revision string
	// Approximate is a link to a branch the product names for the path,
	// because the upload stated no repository for it.
	Approximate bool
	// Patched is a repository whose working tree differed from its commit
	// when it was analyzed: the link shows the source before the patch.
	Patched bool
	// Unlinked says why there is no address, where there is none.
	Unlinked string
}

// Why a location opens nowhere.
const (
	NoRepository = "no repository is known for the path"
	NoHost       = "the repository is on no host the product links to"
	NotACommit   = "the revision is not a commit"
	NotAPath     = "the path does not stay inside the repository"
)

// commit is a revision a link may open at.
var commit = regexp.MustCompile(`^[0-9a-fA-F]{7,64}$`)

// File is where lines of a file open, in the run whose repositories modules
// is. The repository is the one holding the path with the longest prefix,
// and the rest of the path is within it. Where the run names none, a
// repository the product names for the path gives an approximate link.
func (c Config) File(modules []Module, path string, start, end int) Link {
	at, ok := c.locate(modules, path)
	if !ok {
		return Link{Unlinked: NoRepository}
	}
	link := Link{Repository: WithoutCredential(at.remote), Within: at.within, Revision: at.revision,
		Approximate: at.approximate, Patched: at.patched}
	host, repo, ok := c.repository(at.remote)
	if !ok {
		link.Unlinked = NoHost
		return link
	}
	link.Repository = repo
	if !at.approximate && !commit.MatchString(at.revision) {
		link.Unlinked = NotACommit
		return link
	}
	within, ok := escapedPath(at.within)
	if !ok {
		link.Unlinked = NotAPath
		return link
	}
	t := host.fileTemplate()
	if start <= 0 {
		t, _, _ = strings.Cut(t, "#")
	}
	if end < start {
		end = start
	}
	address := strings.NewReplacer(
		"{repo}", repo, "{commit}", escapedRevision(at.revision), "{path}", within,
		"{start}", strconv.Itoa(start), "{end}", strconv.Itoa(end),
	).Replace(t)
	if !on(address, host.Web) {
		link.Unlinked = NoHost
		return link
	}
	link.URL = address
	return link
}

// Compare is the address comparing the repository a path is in between two
// runs, and whether its commit is the same in both and neither run's working
// tree differed from it, which says a disappearance between them is not a
// change to that code. A patch applied at build time is a change the commit
// does not show. Empty where either run names no commit for it, or its host
// has no comparison.
func (c Config) Compare(before, after []Module, path string) (address string, unchanged bool) {
	from, ok := c.locate(before, path)
	if !ok || from.approximate {
		return "", false
	}
	to, ok := c.locate(after, path)
	if !ok || to.approximate || to.module != from.module {
		return "", false
	}
	if !commit.MatchString(from.revision) || !commit.MatchString(to.revision) {
		return "", false
	}
	if strings.EqualFold(from.revision, to.revision) {
		return "", !from.patched && !to.patched
	}
	host, repo, ok := c.repository(from.remote)
	if !ok {
		return "", false
	}
	t := host.compareTemplate()
	if t == "" {
		return "", false
	}
	address = strings.NewReplacer("{repo}", repo, "{from}", from.revision, "{to}", to.revision).Replace(t)
	if !on(address, host.Web) {
		return "", false
	}
	return address, false
}

// CommitOf is the commit the repository holding a path was at in a run: the
// run's repository with the longest prefix holding it, or the top of the
// checkout's commit where none does. Empty where that is not a commit.
func CommitOf(modules []Module, top, path string) string {
	inner := -1
	for i, m := range modules {
		if under(path, m.Path) && (inner < 0 || len(m.Path) > len(modules[inner].Path)) {
			inner = i
		}
	}
	revision := top
	if inner >= 0 {
		revision = modules[inner].Revision
	}
	if !commit.MatchString(revision) {
		return ""
	}
	return strings.ToLower(revision)
}

// Snippets is whether source under a path is kept: the setting of the
// longest prefix that states one, and off where none does.
func (c Config) Snippets(path string) bool {
	best, keep := -1, false
	for _, p := range c.Paths {
		if p.Snippets != nil && under(path, p.Prefix) && len(p.Prefix) > best {
			best, keep = len(p.Prefix), *p.Snippets
		}
	}
	return keep
}

// DisclosesSnippets is whether the snippets under a path of a lead moved into
// a case are disclosed with its flaw: the setting of the longest prefix that
// states one, and off where none does.
func (c Config) DisclosesSnippets(path string) bool {
	best, disclose := -1, false
	for _, p := range c.Paths {
		if p.DisclosedSnippets != nil && under(path, p.Prefix) && len(p.Prefix) > best {
			best, disclose = len(p.Prefix), *p.DisclosedSnippets
		}
	}
	return disclose
}

// located is the repository a path is in, and where in it.
type located struct {
	module      string
	remote      string
	revision    string
	within      string
	approximate bool
	patched     bool
}

// locate is the repository holding a path: the run's repository with the
// longest prefix, its remote read against the repository holding it where it
// is relative, or else the repository the product names for the path.
func (c Config) locate(modules []Module, path string) (located, bool) {
	inner := -1
	for i, m := range modules {
		if under(path, m.Path) && (inner < 0 || len(m.Path) > len(modules[inner].Path)) {
			inner = i
		}
	}
	if inner >= 0 {
		m := modules[inner]
		remote := m.Remote
		if relative(remote) {
			remote = resolve(parentRemote(modules, inner), remote)
		}
		return located{
			module: m.Path, remote: remote, revision: m.Revision,
			within: strings.TrimPrefix(strings.TrimPrefix(path, m.Path), "/"), patched: m.Changed,
		}, remote != ""
	}
	best := -1
	for i, p := range c.Paths {
		if p.Remote != "" && under(path, p.Prefix) && (best < 0 || len(p.Prefix) > len(c.Paths[best].Prefix)) {
			best = i
		}
	}
	if best < 0 {
		return located{}, false
	}
	p := c.Paths[best]
	return located{
		module: p.Prefix, remote: p.Remote, revision: p.Branch,
		within: strings.TrimPrefix(strings.TrimPrefix(path, p.Prefix), "/"), approximate: true,
	}, true
}

// parentRemote is the remote of the repository holding module i, itself
// read against its own parent where it too is relative.
func parentRemote(modules []Module, i int) string {
	parent := -1
	for j, m := range modules {
		if j != i && m.Path != modules[i].Path && under(modules[i].Path, m.Path) &&
			(parent < 0 || len(m.Path) > len(modules[parent].Path)) {
			parent = j
		}
	}
	if parent < 0 {
		return ""
	}
	remote := modules[parent].Remote
	if relative(remote) {
		return resolve(parentRemote(modules, parent), remote)
	}
	return remote
}

// repository is the host covering a remote, the one with the longest prefix,
// and the repository's web address on it.
func (c Config) repository(remote string) (Host, string, bool) {
	host, path := parse(remote)
	if host == "" || path == "" {
		return Host{}, "", false
	}
	folded := strings.ToLower(host + "/" + path)
	best := -1
	for i, h := range c.Hosts {
		if (folded == h.Remote || strings.HasPrefix(folded, h.Remote+"/")) &&
			(best < 0 || len(h.Remote) > len(c.Hosts[best].Remote)) {
			best = i
		}
	}
	if best < 0 {
		return Host{}, "", false
	}
	h := c.Hosts[best]
	skip := strings.Count(h.Remote, "/")
	segments := strings.Split(path, "/")
	if skip >= len(segments) {
		return Host{}, "", false
	}
	rest, ok := escapedPath(strings.Join(segments[skip:], "/"))
	if !ok {
		return Host{}, "", false
	}
	return h, h.Web + "/" + rest, true
}

// fileTemplate is the address a host writes a file's lines at.
func (h Host) fileTemplate() string {
	if h.Style == Custom {
		return h.FileTemplate
	}
	return templates[h.Style][0]
}

// compareTemplate is the address a host compares two commits at, empty where
// a custom host states none.
func (h Host) compareTemplate() string {
	if h.Style == Custom {
		return h.CompareTemplate
	}
	return templates[h.Style][1]
}

// under is whether a path is a prefix or within it. The empty prefix holds
// every path.
func under(path, prefix string) bool {
	return prefix == "" || path == prefix || strings.HasPrefix(path, prefix+"/")
}

// escapedPath is a path with each segment percent-encoded, refused where a
// segment is empty or climbs out. A question mark or a hash in a file name
// would otherwise end the path and steer the link.
func escapedPath(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	segments := strings.Split(p, "/")
	for i, s := range segments {
		if s == "" || s == "." || s == ".." {
			return "", false
		}
		segments[i] = url.PathEscape(s)
	}
	return strings.Join(segments, "/"), true
}

// escapedRevision is a commit, or a branch with each segment escaped. A
// branch is the product's own statement and may hold a slash, which a host
// reads as part of the branch.
func escapedRevision(r string) string {
	segments := strings.Split(r, "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	return strings.Join(segments, "/")
}

// on is whether an address opens over https on the host a web address
// names.
func on(address, web string) bool {
	u, err := url.Parse(address)
	w, werr := url.Parse(web)
	return err == nil && werr == nil && u.Scheme == "https" && u.User == nil &&
		strings.EqualFold(u.Host, w.Host)
}
