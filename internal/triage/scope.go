// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import "github.com/nexthop-ai/openpsirt/internal/refusal"

// Scope is whom a published statement made from a claim holds for.
//
// A statement about a component either holds for anybody shipping that
// component at that version, or holds only for this product's own build of it.
// A fork of the product differs in a few places and shares the rest, so which
// of the two a statement is decides whether somebody else may take it as it
// stands or has to review it against their own build.
type Scope string

const (
	// Portable holds for anybody shipping the component at that version: the
	// vulnerable code is not in it, or the match was wrong.
	Portable Scope = "portable"
	// BuildSpecific holds only for this product's build: the code is compiled
	// out, configured off, never called, already fixed by a patch the build
	// carries, or stopped by something around it.
	BuildSpecific Scope = "build"
)

// Scopes is every scope a claim may state, in the order they are offered.
func Scopes() []Scope { return []Scope{Portable, BuildSpecific} }

// Valid reports whether s is a scope a claim may state.
func (s Scope) Valid() bool { return s == Portable || s == BuildSpecific }

// ScopeOf is whom a statement made from a claim holds for: what the claim
// states where it states one, and what its outcome and reason say otherwise.
//
// The reason decides because it is what the statement rests on. That the
// vulnerable code or the component is absent is a fact about the component,
// and so is a match that was wrong; every other reason, and every outcome
// that is not a dismissal, is a fact about how this product builds, configures
// or patches it. Code that ships and is never called is about this build too:
// another build of the same component calls what it calls.
func ScopeOf(outcome Outcome, justification Justification, stated Scope) Scope {
	if stated.Valid() {
		return stated
	}
	switch {
	case outcome == Mismatched:
		return Portable
	case outcome == NotApplicable && justification.AboutIdentity():
		return Portable
	}
	return BuildSpecific
}

// scoped refuses a scope a claim cannot state.
//
// Empty states none, which is what nearly every claim does. A deferral
// publishes nothing, so a scope on one would be a value nothing reads.
func scoped(outcome Outcome, stated Scope) error {
	switch {
	case stated == "":
		return nil
	case !stated.Valid():
		return refusal.Errorf("%q is not whom a statement holds for: say %q or %q, or nothing "+
			"to let the reason decide", stated, Portable, BuildSpecific)
	case outcome == Deferred:
		return refusal.Errorf("%q says nothing about the component a reader could take, so it "+
			"states nobody it holds for", outcome)
	}
	return nil
}

// scopeOf is a stated scope, or none.
func scopeOf(stated *Scope) Scope {
	if stated == nil {
		return ""
	}
	return *stated
}
