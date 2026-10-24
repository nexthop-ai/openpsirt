// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"net/url"
	"path"
	"strings"
)

// rootBases are the names a run gives its source root, in the order they are
// preferred. The format suggests the first; tools write either.
var rootBases = []string{"SRCROOT", "%SRCROOT%"}

// Paths places a run's file addresses in its checkout.
type Paths struct {
	// root is the checkout's own address, with a trailing slash, where the run
	// states one.
	root string
	// modules is each repository's place, relative to the root, with a
	// trailing slash, in the order the run lists them.
	modules []string
	run     *Run
}

// PathsOf is what places the run's addresses. root is the checkout's
// absolute path as the pipeline states it, used where the run names none.
func PathsOf(run *Run, root string) Paths {
	p := Paths{run: run}
	if abs, ok := absoluteOf(root); ok {
		p.root = dir(abs)
	}
	for _, name := range rootBases {
		if base, ok := run.Bases[name]; ok {
			if abs, ok := p.absolute(base.URI, base.Base, 0); ok {
				p.root = dir(abs)
				break
			}
		}
	}
	for _, m := range run.Modules {
		// A repository mapped to nothing is the checkout itself.
		rel, ok := "", true
		if m.URI != "" || m.Base != "" {
			rel, ok = p.place(m.URI, m.Base)
		}
		switch {
		case !ok:
			p.modules = append(p.modules, "\x00")
		case rel == "":
			p.modules = append(p.modules, "")
		default:
			p.modules = append(p.modules, dir(rel))
		}
	}
	return p
}

// Relative is an address as a path inside the checkout: slash-separated,
// with no leading slash and no step outside it. It is false for an address
// outside the checkout, and for one this cannot place, which is dropped
// rather than stored: an absolute path names the build host's own layout,
// its user's name included.
func (p Paths) Relative(uri, base string) (string, bool) {
	if uri == "" {
		return "", false
	}
	rel, ok := p.place(uri, base)
	return rel, ok && rel != ""
}

// place is Relative, with the checkout itself placed as the empty path.
func (p Paths) place(uri, base string) (string, bool) {
	abs, ok := p.absolute(uri, base, 0)
	if !ok {
		// A relative address with no starting point, or with the root's name
		// left undefined, is relative to the root. Any other undefined name
		// places it nowhere this can tell.
		if base != "" && !isRoot(base) {
			return "", false
		}
		rel, ok := relativeOf(uri)
		if !ok {
			return "", false
		}
		return clean(rel)
	}
	if p.root == "" || !strings.HasPrefix(fold(abs), fold(p.root)) {
		return "", false
	}
	return clean(abs[len(p.root):])
}

// Module is the position, in the run's list, of the repository a path in the
// checkout falls in: the one placed deepest that holds it. It is false where
// none does.
func (p Paths) Module(rel string) (int, bool) {
	best, at := -1, -1
	for i, m := range p.modules {
		if m == "\x00" {
			continue
		}
		if (m == "" || strings.HasPrefix(rel, m)) && len(m) > best {
			best, at = len(m), i
		}
	}
	return at, at >= 0
}

// Within is a path relative to the repository at position i.
func (p Paths) Within(i int, rel string) string {
	return strings.TrimPrefix(rel, p.modules[i])
}

// absolute resolves an address through its chain of named starting points to
// an absolute one: a file URI's path, or an absolute path written bare. It is
// false where the chain ends at an undefined name. Reading refused a run whose
// chain loops, and the depth is bounded again here so that a run built by hand
// cannot recurse without end.
func (p Paths) absolute(uri, base string, depth int) (string, bool) {
	if depth > len(p.run.Bases) {
		return "", false
	}
	if abs, ok := absoluteOf(uri); ok {
		return abs, true
	}
	if base == "" {
		return "", false
	}
	next, ok := p.run.Bases[base]
	if !ok || next.URI == "" {
		return "", false
	}
	prefix, ok := p.absolute(next.URI, next.Base, depth+1)
	if !ok {
		return "", false
	}
	rel, ok := relativeOf(uri)
	if !ok {
		return "", false
	}
	return dir(prefix) + rel, true
}

// absoluteOf is an address's absolute path, where it is one: a file URI, an
// absolute path, or a drive-letter path, with backslashes as slashes.
func absoluteOf(uri string) (string, bool) {
	s := strings.ReplaceAll(uri, `\`, "/")
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && len(u.Scheme) > 1 {
		if !strings.EqualFold(u.Scheme, "file") {
			return "", false
		}
		p := u.Path
		if drive(strings.TrimPrefix(p, "/")) {
			p = strings.TrimPrefix(p, "/")
		}
		return p, p != ""
	}
	if strings.HasPrefix(s, "/") || drive(s) {
		return s, true
	}
	return "", false
}

// relativeOf is a relative address as a path: percent escapes decoded, and
// backslashes as slashes. It is false for an address with a scheme.
func relativeOf(uri string) (string, bool) {
	s := strings.ReplaceAll(uri, `\`, "/")
	if u, err := url.Parse(s); err == nil {
		if u.Scheme != "" && !drive(s) {
			return "", false
		}
		if u.Scheme == "" {
			return u.Path, true
		}
	}
	return s, true
}

// drive is whether a path begins with a drive letter.
func drive(s string) bool {
	return len(s) >= 3 && s[1] == ':' && s[2] == '/' &&
		(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z')
}

// clean is a relative path with no step outside where it starts, and empty
// for where it starts.
func clean(rel string) (string, bool) {
	if strings.HasPrefix(rel, "/") || drive(rel) {
		return "", false
	}
	c := path.Clean(rel)
	if c == "." {
		return "", true
	}
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", false
	}
	return c, true
}

// dir is an address with one trailing slash.
func dir(s string) string {
	if strings.HasSuffix(s, "/") {
		return s
	}
	return s + "/"
}

// fold is a path compared as a drive letter is: without regard to its case.
// The rest of the path is compared exactly.
func fold(s string) string {
	if drive(s) {
		return strings.ToLower(s[:1]) + s[1:]
	}
	return s
}

func isRoot(base string) bool {
	for _, name := range rootBases {
		if base == name {
			return true
		}
	}
	return false
}
