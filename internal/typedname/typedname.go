// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package typedname holds the one rule for matching a name somebody typed.
//
// A leaf beside refusal, so every store that keys a row on a typed name can import it
// whatever else it depends on.
package typedname

import (
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Matching is the form a name somebody typed is stored and matched in.
//
// Lower case and trimmed. These names get typed by hand into build scripts and
// forms, so "sonic" reaching a product declared as "SONiC" is the same typo
// problem that declaring-before-use exists to catch — and refusing it teaches
// somebody the thing is not declared when it plainly is.
//
// Normalizing the stored value rather than comparing case-insensitively is
// what makes every engine agree without any of them being asked to: a
// lower-case value compares the same under any collation, and the unique
// constraint means the same thing everywhere.
//
// The spelling somebody typed is kept beside it and is what gets shown back.
func Matching(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Addressable refuses a name that is a dot segment, for a name that becomes a
// path segment in the addresses about what it names.
//
// A browser resolves "." and ".." before the request is sent, percent-encoded
// or not, so the thing could never be opened and a request about it would
// reach the address above it: removing a team member named ".." would ask to
// delete the team. Checked on the name as typed and as stored.
func Addressable(what, name string) error {
	if DotSegment(name) || DotSegment(Matching(name)) {
		return refusal.Errorf("%s %q is a path segment a browser resolves rather than sends", what, name)
	}
	return nil
}

// DotSegment reports whether a name is "." or "..", which a browser resolves
// as a path segment rather than sending.
func DotSegment(name string) bool { return name == "." || name == ".." }
