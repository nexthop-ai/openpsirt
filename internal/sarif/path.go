// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"path"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/sarif/uribase"
)

// Paths places a run's file addresses in its checkout.
type Paths struct {
	// root is the checkout's own address, with a trailing slash, where the run
	// states one.
	root string
	// working is where the tool was run, relative to the root, with a
	// trailing slash, or empty where the run states no working directory
	// inside the checkout.
	working string
	// modules is each repository's place, relative to the root, with a
	// trailing slash, in the order the run lists them.
	modules []string
	run     *Run
}

// PathsOf is what places the run's addresses. root is the checkout's
// absolute path as the pipeline states it, used where the run names none.
func PathsOf(run *Run, root string) Paths {
	p := Paths{run: run}
	if abs, ok := uribase.AbsolutePath(root); ok {
		p.root = dir(abs)
	}
	for _, name := range uribase.RootNames {
		if base, ok := run.Bases[name]; ok {
			if abs, start, ok := uribase.Resolve(base.URI, base.Base, p.defined, len(run.Bases)); ok && start == uribase.Absolute {
				p.root = dir(abs)
				break
			}
		}
	}
	// An address with no starting point is relative to where the tool was
	// run. The first invocation stating a working directory says where.
	for _, inv := range run.Invocations {
		wd := inv.WorkingDirectory
		if wd.URI == "" {
			continue
		}
		if rel, ok := p.place(wd.URI, wd.Base); ok && rel != "" {
			p.working = dir(rel)
		}
		break
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

// place is Relative, with the checkout itself placed as the empty path. An
// address whose chain ends at the root's undefined name is relative to the
// root, and one ending at no starting point is relative to where the tool
// was run, the root where the run does not say.
func (p Paths) place(uri, base string) (string, bool) {
	at, start, ok := uribase.Resolve(uri, base, p.defined, len(p.run.Bases))
	switch {
	case !ok:
		return "", false
	case start == uribase.FromRoot:
		return clean(at)
	case start == uribase.FromWork:
		return clean(p.working + at)
	}
	// The root itself is the checkout, written with or without its slash.
	at = dir(at)
	if p.root == "" || !strings.HasPrefix(fold(at), fold(p.root)) {
		return "", false
	}
	return clean(at[len(p.root):])
}

// defined is the run's named starting points, as Resolve reads them.
func (p Paths) defined(name string) (string, string, bool) {
	b, ok := p.run.Bases[name]
	return b.URI, b.Base, ok && b.URI != ""
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

// ModulePath is where the repository at position i sits in the checkout,
// with no trailing slash and empty for the checkout itself. It is false for
// one the run places nowhere this can tell.
func (p Paths) ModulePath(i int) (string, bool) {
	if i < 0 || i >= len(p.modules) || p.modules[i] == "\x00" {
		return "", false
	}
	return strings.TrimSuffix(p.modules[i], "/"), true
}

// Within is a path relative to the repository at position i.
func (p Paths) Within(i int, rel string) string {
	return strings.TrimPrefix(rel, p.modules[i])
}

// clean is a relative path with no step outside where it starts, and empty
// for where it starts.
func clean(rel string) (string, bool) {
	if strings.HasPrefix(rel, "/") || uribase.Drive(rel) {
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
	if uribase.Drive(s) {
		return strings.ToLower(s[:1]) + s[1:]
	}
	return s
}
