// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package uribase resolves a SARIF address through its chain of named
// starting points, as the upload client and the deployment both read one. It
// imports nothing of ours, so the client carries it without the reader.
package uribase

import (
	"net/url"
	"strings"
)

// RootNames are the names a run gives its source root, in the order they are
// preferred. The format suggests the first; tools write either.
var RootNames = []string{"SRCROOT", "%SRCROOT%"}

// IsRoot is whether a starting point's name is one the source root goes by.
func IsRoot(name string) bool {
	for _, root := range RootNames {
		if name == root {
			return true
		}
	}
	return false
}

// Start is what a resolved address is relative to.
type Start int

const (
	// Absolute is an absolute path, relative to nothing.
	Absolute Start = iota
	// FromRoot is relative to the source root, its name left undefined.
	FromRoot
	// FromWork is relative to where the tool ran: the chain ends at an
	// address with no starting point.
	FromWork
)

// Defined is a run's named starting points as Resolve reads them: a name's own
// address and the starting point that address is relative to. It is false for
// a name the run leaves undefined or defines with no address.
type Defined func(name string) (uri, base string, ok bool)

// Resolve resolves an address through its chain of named starting points. It
// is an absolute path, or a relative path with what it is relative to: the
// source root, where the chain ends at the root's undefined name, or where
// the tool ran, where it ends at no name. It is false where the chain ends at
// any other undefined name, an address has a scheme other than file, or the
// chain passes through more than most starting points.
func Resolve(uri, base string, defined Defined, most int) (string, Start, bool) {
	return resolve(uri, base, defined, most, 0)
}

func resolve(uri, base string, defined Defined, most, depth int) (string, Start, bool) {
	if depth > most {
		return "", Absolute, false
	}
	if abs, ok := AbsolutePath(uri); ok {
		return abs, Absolute, true
	}
	rel, ok := RelativePath(uri)
	if !ok {
		return "", Absolute, false
	}
	if base == "" {
		return rel, FromWork, true
	}
	next, nextBase, ok := defined(base)
	if !ok {
		if IsRoot(base) {
			return rel, FromRoot, true
		}
		return "", Absolute, false
	}
	prefix, start, ok := resolve(next, nextBase, defined, most, depth+1)
	if !ok {
		return "", Absolute, false
	}
	if prefix == "" {
		return rel, start, true
	}
	return strings.TrimSuffix(prefix, "/") + "/" + rel, start, true
}

// AbsolutePath is an address's absolute path, where it is one: a file URI's
// path, an absolute path, or a drive-letter path, with backslashes as slashes.
func AbsolutePath(uri string) (string, bool) {
	s := strings.ReplaceAll(uri, `\`, "/")
	if Drive(s) {
		return s, true
	}
	if u, err := url.Parse(s); err == nil && u.Scheme != "" {
		if !strings.EqualFold(u.Scheme, "file") {
			return "", false
		}
		p := u.Path
		if Drive(strings.TrimPrefix(p, "/")) {
			p = strings.TrimPrefix(p, "/")
		}
		return p, p != ""
	}
	if strings.HasPrefix(s, "/") {
		return s, true
	}
	return "", false
}

// RelativePath is a relative address as a path: percent escapes decoded, and
// backslashes as slashes. It is false for an address with a scheme.
func RelativePath(uri string) (string, bool) {
	s := strings.ReplaceAll(uri, `\`, "/")
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return s, true
	case u.Scheme != "":
		return "", false
	}
	return u.Path, true
}

// Drive is whether a path begins with a drive letter.
func Drive(s string) bool {
	return len(s) >= 3 && s[1] == ':' && s[2] == '/' &&
		(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z')
}
