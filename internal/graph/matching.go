// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Unmatchable is why the scanner has no way to match a component against any
// vulnerability data, or empty where it has one.
//
// A component nothing can match reports no findings, which is also what a
// component with none reports. Each reason is a shape the scanner was measured
// answering nothing for; DESIGN-reporting.md § Match coverage holds the
// measurements.
type Unmatchable string

// The reasons, in the order a component is tested against them. A component
// that fails several is reported under the first: one without a version is
// unmatchable whatever its distribution says.
const (
	// NoIdentifier is a component with no package identifier. A CPE alone
	// matches nothing.
	NoIdentifier Unmatchable = "no-identifier"
	// UnpublishedKind is a package type no vulnerability data is published
	// against: a container image, a source repository.
	UnpublishedKind Unmatchable = "unpublished-kind"
	// NoVersion is a component whose version is absent, or is a word saying
	// nobody knows it.
	NoVersion Unmatchable = "no-version"
	// NoDistribution is a distribution's package whose identifier does not say
	// which release of the distribution it was built for, which is how the
	// scanner picks the advisories to match it against.
	NoDistribution Unmatchable = "no-distribution"
	// GenericWithoutCPE is a component of the generic type with no CPE. The
	// type names no ecosystem, so the CPE is the only thing to match on.
	GenericWithoutCPE Unmatchable = "generic-without-cpe"
)

// Reasons is every reason, in the order a component is tested against them.
var Reasons = []Unmatchable{NoIdentifier, UnpublishedKind, NoVersion, NoDistribution, GenericWithoutCPE}

// unpublished is the package types the scanner was measured matching nothing
// for, whatever the component.
var unpublished = map[string]bool{"oci": true, "github": true}

// distributions is the package types whose advisories are chosen by the
// distribution release the identifier states.
var distributions = map[string]bool{"deb": true, "rpm": true, "apk": true}

// Unmatchable reports why the scanner cannot match this component, or empty
// where it can.
//
// It reads what the scanner is given: the stored identifier with the
// distribution worked out the way the scanner's inventory works it out, from
// `distro` or from `os_name` and `os_version`.
func (d Described) Unmatchable() Unmatchable {
	parts := PartsOfPurl(d.Purl)
	switch {
	case parts.Type == "":
		return NoIdentifier
	case unpublished[parts.Type]:
		return UnpublishedKind
	case unversioned(d.Version):
		return NoVersion
	case distributions[parts.Type] && parts.Distro == "":
		return NoDistribution
	case parts.Type == "generic" && strings.TrimSpace(d.CPE) == "":
		return GenericWithoutCPE
	}
	return ""
}

// unversioned is a version that says nobody knows it. "UNKNOWN" is what a
// scanner of a filesystem writes for a kernel module, and "(devel)" what the Go
// toolchain records for a module built from a working tree.
func unversioned(version string) bool {
	version = strings.TrimSpace(version)
	return version == "" || strings.EqualFold(version, "unknown") || version == "(devel)"
}

// Unmatched is one component of a build the scanner has no way to match.
type Unmatched struct {
	Name    string
	Version string
	Purl    string
	CPE     string
	Reason  Unmatchable
}

// Unmatched lists the components a build holds now that the scanner has no way
// to match, ordered by reason and then by name and version, with how many
// components the build holds in all.
//
// Worked out when asked, from the same rows the scanner is given. A build
// holds thousands of components rather than millions, and the reasons are read
// from an identifier's qualifiers, which no engine parses alike.
func (s *Store) Unmatched(ctx context.Context, subject access.Subject, targetID int64) ([]Unmatched, int, error) {
	if _, _, err := s.visibleIn(ctx, subject, targetID); err != nil {
		return nil, 0, err
	}
	held, err := s.CurrentComponents(ctx, targetID)
	if err != nil {
		return nil, 0, err
	}
	var out []Unmatched
	for _, d := range held {
		if reason := d.Unmatchable(); reason != "" {
			out = append(out, Unmatched{
				Name: d.Name, Version: d.Version, Purl: d.Purl, CPE: d.CPE, Reason: reason,
			})
		}
	}
	rank := make(map[Unmatchable]int, len(Reasons))
	for i, reason := range Reasons {
		rank[reason] = i
	}
	slices.SortFunc(out, func(a, b Unmatched) int {
		return cmp.Or(
			cmp.Compare(rank[a.Reason], rank[b.Reason]),
			cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)),
			cmp.Compare(a.Version, b.Version),
			cmp.Compare(a.Purl, b.Purl),
		)
	})
	return out, len(held), nil
}

// unmatchedCount is how many of a build's current components the scanner has
// no way to match.
func (s *Store) unmatchedCount(ctx context.Context, targetID int64) (int, error) {
	held, err := s.CurrentComponents(ctx, targetID)
	if err != nil {
		return 0, fmt.Errorf("read what this build holds: %w", err)
	}
	count := 0
	for _, d := range held {
		if d.Unmatchable() != "" {
			count++
		}
	}
	return count, nil
}
