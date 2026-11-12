// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package uploadclient

import (
	"net/url"
	"path"
	"path/filepath"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/sarif/uribase"
)

// rootBase is the starting point every path inside the checkout is written
// relative to. It is left undefined, so no document names where the checkout
// sits on the build host.
const rootBase = "SRCROOT"

// placer writes every path as the deployment reads it: inside the checkout,
// relative to its top with forward slashes and the case the git index gives
// it; outside it, as the absolute address it is, which the deployment drops.
// The same commit gives the same paths on every operating system.
type placer struct {
	// root and work are absolute, slash-separated and without a trailing
	// slash: the top of the checkout, and the directory relative paths in the
	// tool's output are relative to.
	root, work string
	// index is every path the git index holds, by its lower-case form, and
	// exact the same paths as they are.
	index map[string]string
	exact map[string]bool
	// real is the top of the checkout with every link along it followed, and
	// resolved each absolute path outside the checkout as it is with its
	// links followed, empty where it is no file on this host.
	real     string
	resolved map[string]string
}

func newPlacer(root, work string, indexed []string) *placer {
	p := &placer{root: slashed(root), work: slashed(work), index: map[string]string{}, exact: map[string]bool{},
		resolved: map[string]string{}}
	p.real = p.root
	if r, err := filepath.EvalSymlinks(filepath.FromSlash(p.root)); err == nil {
		p.real = slashed(filepath.ToSlash(r))
	}
	for _, f := range indexed {
		f = strings.ReplaceAll(f, `\`, "/")
		p.exact[f] = true
		lower := strings.ToLower(f)
		if prior, ok := p.index[lower]; ok && prior != f {
			// Two paths differing only by case: neither is guessed at.
			p.index[lower] = ""
			continue
		}
		p.index[lower] = f
	}
	return p
}

// slashed is an absolute path with forward slashes and no trailing slash.
func slashed(s string) string {
	s = strings.ReplaceAll(s, `\`, "/")
	if s != "/" && !isDriveRoot(s) {
		s = strings.TrimSuffix(s, "/")
	}
	return s
}

func isDriveRoot(s string) bool { return len(s) == 3 && uribase.Drive(s) }

// placement is where an address resolved to.
type placement int

const (
	// unplaced is an address this cannot resolve: a starting point the
	// document leaves undefined, other than the checkout's.
	unplaced placement = iota
	inside
	outside
)

// rewrite writes an artifact location as it is placed, leaving one it cannot
// place as it was.
func (p *placer) rewrite(art obj, bases map[string]obj) {
	where, at := p.place(str(art, "uri"), str(art, "uriBaseId"), bases)
	switch where {
	case inside:
		art["uri"] = (&url.URL{Path: at}).String()
		art["uriBaseId"] = rootBase
	case outside:
		art["uri"] = fileURI(at)
		delete(art, "uriBaseId")
	}
}

// fileURI is an absolute path as a file address.
func fileURI(abs string) string {
	if uribase.Drive(abs) {
		abs = "/" + abs
	}
	return (&url.URL{Scheme: "file", Path: abs}).String()
}

// place resolves an address through its starting points. It reports a path
// inside the checkout relative to its top, and any other as absolute.
func (p *placer) place(uri, base string, bases map[string]obj) (placement, string) {
	abs, ok := p.absolute(uri, base, bases)
	if !ok {
		return unplaced, ""
	}
	rel, in := p.inside(abs)
	if !in {
		return outside, abs
	}
	return inside, p.cased(rel)
}

// inside is an absolute path relative to the top of the checkout, where it is
// inside it as written or once the links along either are followed. A tool
// run from a directory reached through a link writes paths through the link,
// and git names the checkout without it.
func (p *placer) inside(abs string) (string, bool) {
	for _, root := range []string{p.root, p.real} {
		if rel, ok := within(abs, root); ok {
			return rel, true
		}
	}
	r, ok := p.resolved[abs]
	if !ok {
		if full, err := filepath.EvalSymlinks(filepath.FromSlash(abs)); err == nil {
			r = cleanAbs(filepath.ToSlash(full))
		}
		p.resolved[abs] = r
	}
	if r == "" || r == abs {
		return "", false
	}
	for _, root := range []string{p.root, p.real} {
		if rel, ok := within(r, root); ok {
			return rel, true
		}
	}
	return "", false
}

// maxChain bounds how many starting points one address may pass through.
const maxChain = 16

// absolute is an address as an absolute, slash-separated, cleaned path,
// resolved as the deployment resolves it: a chain ending at the source root's
// undefined name is under the top of the checkout, and one ending at no
// starting point under the directory the tool ran in.
func (p *placer) absolute(uri, base string, bases map[string]obj) (string, bool) {
	at, start, ok := uribase.Resolve(uri, base, func(name string) (string, string, bool) {
		b, ok := bases[name]
		u := str(b, "uri")
		return u, str(b, "uriBaseId"), ok && u != ""
	}, maxChain)
	if !ok {
		return "", false
	}
	switch start {
	case uribase.FromRoot:
		at = under(p.root, at)
	case uribase.FromWork:
		at = under(p.work, at)
	}
	return cleanAbs(at), true
}

// under is a relative path under an absolute directory.
func under(dir, rel string) string {
	if rel == "" {
		return dir
	}
	return strings.TrimSuffix(dir, "/") + "/" + rel
}

// cleanAbs is an absolute path with its dot steps resolved.
func cleanAbs(s string) string {
	if uribase.Drive(s) {
		return s[:2] + path.Clean(s[2:])
	}
	return path.Clean(s)
}

// within is an absolute path relative to root, where it is inside it. A
// drive letter compares without regard to case, and on a drive the whole path
// does, as the file systems that have drives compare it.
func within(abs, root string) (string, bool) {
	same := func(a, b string) bool { return a == b }
	if uribase.Drive(root) || uribase.Drive(abs) {
		same = strings.EqualFold
	}
	if same(abs, root) {
		return "", true
	}
	prefix := strings.TrimSuffix(root, "/") + "/"
	if len(abs) <= len(prefix) || !same(abs[:len(prefix)], prefix) {
		return "", false
	}
	return abs[len(prefix):], true
}

// cased is a path in the case the git index holds it in, where the index holds
// it in exactly one case.
func (p *placer) cased(rel string) string {
	if rel == "" || p.exact[rel] {
		return rel
	}
	if f := p.index[strings.ToLower(rel)]; f != "" {
		return f
	}
	return rel
}
