// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import "strings"

// PurlPrefix is a package identifier somebody typed to choose components by:
// a whole package such as `pkg:github/sonic-net/sonic-swss`, or everything
// under a path such as `pkg:github/sonic-net/`.
//
// Matched against the package a component's identifier names, reduced the
// way identity reduces it: version, qualifiers and subpath cut, escapes
// decoded, the type lowercased. Compared without regard to capitals, as every
// name people type is. It is never part of a statement: a component's
// identifier is read and tested here, so a prefix carries no pattern into SQL.
type PurlPrefix struct {
	// wanted is the typed prefix reduced and folded, and under says it ends
	// on a separator, so it names a path rather than one package.
	wanted string
	under  bool
}

// ParsePurlPrefix reads a typed prefix. A prefix with no `pkg:` scheme or
// nothing after the type names nothing, and reads as the zero value.
func ParsePurlPrefix(typed string) PurlPrefix {
	typed = strings.TrimSpace(typed)
	if cut := strings.IndexAny(typed, "?#"); cut >= 0 {
		typed = typed[:cut]
	}
	scheme, rest, found := strings.Cut(typed, ":")
	if !found || !strings.EqualFold(scheme, "pkg") || !strings.Contains(rest, "/") {
		return PurlPrefix{}
	}
	if strings.HasSuffix(typed, "/") {
		return PurlPrefix{wanted: strings.ToLower(canonicalPurl(typed)), under: true}
	}
	base, _ := PackageOf(typed)
	return PurlPrefix{wanted: strings.ToLower(base)}
}

// Empty is whether the prefix names nothing.
func (p PurlPrefix) Empty() bool { return p.wanted == "" }

// String is the prefix as it is matched.
func (p PurlPrefix) String() string { return p.wanted }

// Matches says whether a component's package identifier names a package the
// prefix chooses: the package itself, or one under it a whole segment at a
// time, so `pkg:github/sonic-net/sonic-swss` takes neither
// `sonic-swss-common` nor a component with no identifier.
func (p PurlPrefix) Matches(purl string) bool {
	if p.wanted == "" {
		return false
	}
	base, _ := PackageOf(purl)
	if base == "" {
		return false
	}
	base = strings.ToLower(base)
	if p.under {
		return strings.HasPrefix(base, p.wanted)
	}
	return base == p.wanted || strings.HasPrefix(base, p.wanted+"/")
}

// PackageName is a component's identifier reduced to the package it names,
// with the version and qualifiers cut, or empty where it has none.
func PackageName(purl string) string {
	base, _ := PackageOf(purl)
	return base
}

// Ecosystem is the type a component's identifier names, lowercased, or empty
// where it has none.
func Ecosystem(purl string) string {
	return PartsOfPurl(purl).Type
}
