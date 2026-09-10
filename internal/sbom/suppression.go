package sbom

import (
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Status is what a build says about a vulnerability in something it ships.
//
// The vocabulary is the exchange format's, kept rather than translated: a
// build that says "we carry the fix" and one that says "the vulnerable code is
// never reached" are making different claims, and collapsing them here would
// lose the distinction before anyone triaging ever sees it.
type Status string

const (
	// NotAffected means the build says the vulnerability does not apply to it.
	NotAffected Status = "not_affected"
	// Affected means it does apply and the build knows.
	Affected Status = "affected"
	// AlreadyFixed means it applied and the shipped version resolves it —
	// which is what a carried patch does.
	AlreadyFixed Status = "fixed"
	// UnderInvestigation means the build has not decided.
	UnderInvestigation Status = "under_investigation"
)

// known reports whether a status is one we can act on.
func (s Status) known() bool {
	switch s {
	case NotAffected, Affected, AlreadyFixed, UnderInvestigation:
		return true
	}
	return false
}

// Suppresses reports whether a claim removes a finding from what someone has
// to triage. The other two are information: they say the build looked, not
// that there is nothing to do.
func (s Status) Suppresses() bool { return s == NotAffected || s == AlreadyFixed }

// Origin says where a claim was read from, because the two differ in how
// precisely they point at anything.
type Origin string

const (
	// FromStatement is a claim in a suppression document. It names what it
	// applies to by package identifier, which may be a whole family rather
	// than one component.
	FromStatement Origin = "statement"
	// FromPedigree is a claim the inventory carries on a component itself —
	// a patch recording which vulnerability it fixes. It needs no matching:
	// it arrived attached to the thing it is about.
	FromPedigree Origin = "pedigree"
)

// Suppression is one claim a build makes about a vulnerability.
type Suppression struct {
	// Vulnerability is the identifier the claim was made against, and Aliases
	// are the other identifiers for the same issue. Identity spans them: which
	// one a producer chose is a preference of whichever database it consulted,
	// not a property of the issue.
	Vulnerability string
	Aliases       []string
	Status        Status
	// Justification is the vocabulary term the claim gives for a status of
	// not affected, and Statement is what was written alongside it.
	Justification string
	Statement     string
	// Targets are what the claim points at. A claim with none applies to
	// nothing, which is worth seeing rather than silently discarding.
	Targets []Target
	Origin  Origin
}

// Target is what a claim points at, as a package identifier.
//
// A claim that names no version applies to every version of what it names —
// the format says so, and it is how a build states something about whatever it
// happens to ship.
type Target struct {
	Purl string
	// Name is used where the identifier cannot point at a component: a claim
	// made against a source tree rather than a package. The build knows which
	// packages came out of that tree and we do not, so the most that can be
	// said is that a component of the same name is the one meant.
	Name string
}

// Covers reports whether a claim's target is the component described.
func (t Target) Covers(d graph.Described) bool {
	base, version := purlParts(t.Purl)
	if base == "" {
		return false
	}
	if strings.HasPrefix(base, "pkg:generic/") {
		named := strings.TrimPrefix(base, "pkg:generic/")
		return equalName(named, d.Name) || equalName(named, d.UpstreamName)
	}
	componentBase, componentVersion := purlParts(d.Purl)
	if componentBase != base {
		return false
	}
	if version == "" {
		return true
	}
	if componentVersion == "" {
		componentVersion = d.Version
	}
	return version == componentVersion
}

// Covers reports whether any of a claim's targets is the component described.
func (s Suppression) Covers(d graph.Described) bool {
	for _, t := range s.Targets {
		if t.Covers(d) {
			return true
		}
	}
	return false
}

// purlParts splits a package identifier into what it names and the version it
// names, discarding the qualifiers and the subpath.
//
// Qualifiers have to go: a claim is written as the package and the version,
// while the same package in an inventory carries the architecture it was built
// for. Comparing the two as written would match nothing.
func purlParts(purl string) (base, version string) {
	base = strings.TrimSpace(purl)
	if cut := strings.IndexAny(base, "?#"); cut >= 0 {
		base = base[:cut]
	}
	// The version is what follows the last "@" — but only when there is
	// something before it. A scoped name in some ecosystems begins with one
	// ("pkg:npm/@babel/core"), and splitting there would leave a claim naming
	// a package type and a version of "babel/core", matching nothing and
	// saying nothing about why.
	if at := strings.LastIndex(base, "@"); at > 0 && base[at-1] != '/' {
		base, version = base[:at], base[at+1:]
	}
	return base, version
}

// equalName compares names the way an identifier does, which is without regard
// to case.
func equalName(a, b string) bool {
	return a != "" && b != "" && strings.EqualFold(a, b)
}
