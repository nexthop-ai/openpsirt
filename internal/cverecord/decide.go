// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord

import (
	"regexp"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// Verdict is what the records say about one issue in one component.
type Verdict struct {
	// Record is the identifier of the record that was read, or empty where
	// the snapshot holds none for the issue.
	Record string
	// Unaffected is every line stating that the component's version is not
	// affected. Present only where no line of the same entries states that it
	// is, so a verdict with lines here is one that narrows the match.
	Unaffected []Stated
	// BranchFix is the first version on the component's own branch that the
	// record states is unaffected, where the component's version is still
	// affected or unstated. Empty where the record names none.
	BranchFix string
}

// Narrows reports whether the record excludes the component's version.
func (v Verdict) Narrows() bool {
	return len(v.Unaffected) > 0
}

// Stated is a version line beside the entry it belongs to.
type Stated struct {
	Entry string `json:"entry"`
	Line
}

// Decide reads what the record for an issue says about a component.
//
// The identifiers are the issue's own and its aliases, in that order; the
// first the snapshot holds is the record read. Nothing narrows unless an
// upstream entry tied to the component has an ordered unaffected line
// containing the component's upstream version, and no line of those entries
// that could contain it states it is affected.
func (s *Snapshot) Decide(identifiers []string, component graph.Described) Verdict {
	if s == nil {
		return Verdict{}
	}
	var record *Record
	for _, id := range identifiers {
		if held, ok := s.records[strings.ToUpper(strings.TrimSpace(id))]; ok {
			record = held
			break
		}
	}
	if record == nil {
		return Verdict{}
	}
	verdict := Verdict{Record: record.ID}

	version, ok := upstreamVersion(component)
	if !ok {
		return verdict
	}

	var unaffected []Stated
	blocked := false
	fix := ""
	for _, entry := range record.Affected {
		if !tied(entry, component) {
			continue
		}
		for _, line := range entry.Versions {
			switch evaluate(line, version) {
			case containsAffected, unreadableAffected:
				blocked = true
			case containsUnaffected:
				unaffected = append(unaffected, Stated{Entry: entry.Named(), Line: line})
			}
			if first, on := branchFix(line, version); on {
				if fix == "" {
					fix = first
				} else if cmp, ordered := vercmp.Order(vercmp.Semantic, first, fix); ordered && cmp < 0 {
					fix = first
				}
			}
		}
	}
	if blocked || len(unaffected) == 0 {
		verdict.BranchFix = fix
		return verdict
	}
	verdict.Unaffected = unaffected
	return verdict
}

// outcome is what one line says about one version.
type outcome int

const (
	// silent is a line that does not contain the version, or one this does not
	// read at all.
	silent outcome = iota
	containsAffected
	containsUnaffected
	// unreadableAffected is an affected line this cannot place the version
	// against. It might contain the version, so it stops anything narrowing.
	unreadableAffected
)

// evaluate places a version against one line.
//
// A line about commits rather than releases is silent: the kernel's records
// carry one entry of commit ranges beside the entry of releases, and both say
// the same thing. Any other line this cannot order is silent where it states
// unaffected and blocks where it states affected, which is the conservative
// reading of each.
func evaluate(line Line, version string) outcome {
	affected := strings.EqualFold(line.Status, "affected")
	unaffected := strings.EqualFold(line.Status, "unaffected")
	if !affected && !unaffected {
		return silent
	}
	readable := orderedType(line.VersionType) && !line.Changes
	if strings.EqualFold(line.VersionType, "git") ||
		strings.EqualFold(line.VersionType, "original_commit_for_fix") {
		return silent
	}
	in, placed := false, false
	if readable {
		in, placed = contains(line, version)
	}
	switch {
	case !placed && affected:
		return unreadableAffected
	case !placed || !in:
		return silent
	case affected:
		return containsAffected
	default:
		return containsUnaffected
	}
}

// orderedType reports whether a line's version type is one this orders.
//
// A line with no type is read as release numbers, which is how the kernel's
// writes the version a bug arrived in. Everything else — a distribution's
// package versions, a custom scheme, a commit — is not ordered here.
func orderedType(versionType string) bool {
	switch strings.ToLower(strings.TrimSpace(versionType)) {
	case "", "semver":
		return true
	default:
		return false
	}
}

// contains reports whether a version falls inside a line, and whether the line
// could be read at all.
//
// The format's own semantics: a version alone names that version, a lower
// bound with a strict upper bound is a half-open range, and a lower bound with
// an inclusive upper bound is a closed one, where the upper bound may end in a
// wildcard covering every release that begins with it.
func contains(line Line, version string) (in, readable bool) {
	from := strings.TrimSpace(line.Version)
	below, upTo := strings.TrimSpace(line.LessThan), strings.TrimSpace(line.LessThanOrEqual)
	cmp, ok := vercmp.Order(vercmp.Semantic, from, version)
	if !ok {
		return false, false
	}
	switch {
	case below != "" && upTo != "":
		return false, false
	case below != "":
		upper, ok := vercmp.Order(vercmp.Semantic, version, below)
		if !ok {
			return false, false
		}
		return cmp <= 0 && upper < 0, true
	case upTo != "":
		within, ok := atMost(version, upTo)
		if !ok {
			return false, false
		}
		return cmp <= 0 && within, true
	default:
		return cmp == 0, true
	}
}

// atMost reports whether a version is at or below an inclusive upper bound,
// which may be a wildcard.
func atMost(version, bound string) (bool, bool) {
	if bound == "*" {
		return true, true
	}
	if prefix, wild := strings.CutSuffix(bound, ".*"); wild {
		parts := strings.Split(prefix, ".")
		head, ok := leading(version, len(parts))
		if !ok {
			return false, false
		}
		cmp, ok := vercmp.Order(vercmp.Semantic, head, prefix)
		return ok && cmp <= 0, ok
	}
	cmp, ok := vercmp.Order(vercmp.Semantic, version, bound)
	return ok && cmp <= 0, ok
}

// leading is the first n dotted parts of a version's release, padded with
// zeros where it has fewer.
func leading(version string, n int) (string, bool) {
	release, _, _ := strings.Cut(version, "-")
	release, _, _ = strings.Cut(release, "+")
	parts := strings.Split(release, ".")
	if release == "" || n < 1 {
		return "", false
	}
	for len(parts) < n {
		parts = append(parts, "0")
	}
	return strings.Join(parts[:n], "."), true
}

// branchFix is the first version a line states is unaffected, where the line
// covers the rest of the component's own branch and its first version is past
// the component's.
//
// A branch is what a wildcard bound names: "6.18.27" up to "6.18.*" is the
// 6.18 branch from 6.18.27 on. That is the release to move to without leaving
// the branch, which a scanner's range cut from another branch does not say.
func branchFix(line Line, version string) (string, bool) {
	if !strings.EqualFold(line.Status, "unaffected") || !orderedType(line.VersionType) || line.Changes {
		return "", false
	}
	bound := strings.TrimSpace(line.LessThanOrEqual)
	prefix, wild := strings.CutSuffix(bound, ".*")
	if !wild || strings.TrimSpace(line.LessThan) != "" {
		return "", false
	}
	first := strings.TrimSpace(line.Version)
	head, ok := leading(version, len(strings.Split(prefix, ".")))
	if !ok {
		return "", false
	}
	if same, ok := vercmp.Order(vercmp.Semantic, head, prefix); !ok || same != 0 {
		return "", false
	}
	if past, ok := vercmp.Order(vercmp.Semantic, first, version); !ok || past <= 0 {
		return "", false
	}
	return first, true
}

// upstreamVersion is the release a component's version is, in the upstream
// project's numbering, and whether it has one this can order.
//
// For a distribution's package that is the version with the epoch and the
// packaging revision taken off; for anything else it is the version as given,
// less a leading "v". The result has to be release numbers alone, or nothing
// is narrowed.
func upstreamVersion(component graph.Described) (string, bool) {
	version := strings.TrimSpace(component.UpstreamVersion)
	if version == "" {
		version = strings.TrimSpace(component.Version)
	}
	if distribution(graph.PartsOfPurl(component.Purl).Type) {
		if _, rest, found := strings.Cut(version, ":"); found {
			version = rest
		}
		if cut := strings.LastIndex(version, "-"); cut > 0 {
			version = version[:cut]
		}
	}
	version = strings.TrimPrefix(version, "v")
	if !releaseNumber.MatchString(version) {
		return "", false
	}
	return version, true
}

// releaseNumber is a version that is release numbers and nothing else.
//
// Anything after them is refused rather than read as a pre-release, which is
// what the ordering would make of it: a kernel's "6.18.55-onie" is 6.18.55
// with a vendor's own changes on top, and those changes are what a record
// cannot speak for.
var releaseNumber = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// distribution reports whether a package type is a distribution's own
// packaging, whose versions carry a revision of the distribution's.
func distribution(kind string) bool {
	switch kind {
	case "deb", "rpm", "apk", "alpm":
		return true
	default:
		return false
	}
}
