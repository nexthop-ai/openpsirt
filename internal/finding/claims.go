// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// The build's claims as applying a scan reads them: which ones name an issue,
// which one covers a place, and how many reach anything the build ships.

import (
	"sort"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// claimsReaching counts how many of a build's arguments land on something it
// actually ships.
//
// A claim that reached nothing is the ordinary case rather than the
// exceptional one — a producer's automatically-extracted claims name source
// trees rather than packages — and it means a finding the build believes it
// has answered will come back as noise. Nothing distinguishes that from a
// finding nobody has looked at, so the count is reported rather than left to
// be inferred.
//
// A claim naming a product of the build reaches only what sits beneath it, so
// one naming a release of the product the build does not ship reaches nothing.
func claimsReaching(claims []Claim, present inventory, places consumers,
	p *placer) (reaching, reachingNothing int) {

	for _, claim := range claims {
		found := false
		for _, component := range present.byID {
			if !claim.covers(describedOf(component)) {
				continue
			}
			for _, consumerID := range places.of(component.ID) {
				if p.reaches(claim.within(), component, consumerID) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			reaching++
		} else {
			reachingNothing++
		}
	}
	return reaching, reachingNothing
}

// describedOf reads a stored component back into the shape a claim matches
// against.
func describedOf(c graph.Component) graph.Described {
	return graph.Described{
		Purl: c.Purl, CPE: c.CPE, Name: c.Name, Version: c.Version,
		UpstreamName: c.UpstreamName, UpstreamVersion: c.UpstreamVersion,
	}
}

// coveringClaim finds the build's argument that covers a reported issue at
// one place, if it made one: the claim that suppresses it, and the claim the
// finding names whatever it says.
//
// A claim that arrived attached to the component is preferred over one that
// named something we had to match: the first knows exactly what it is about,
// while the second may name a whole source tree. A claim that suppresses is
// preferred over one saying the flaw applies, which leaves the finding work and
// carries the build's workaround.
//
// The claims are the ones naming the issue, from claimsByName.
func coveringClaim(claims []Claim, component graph.Component, consumerID int64,
	p *placer) (suppressing, claimed *int64) {

	described := describedOf(component)

	var covering []Claim
	latest := map[string]time.Time{}
	for _, claim := range claims {
		if !claim.covers(described) || !p.reaches(claim.within(), component, consumerID) {
			continue
		}
		covering = append(covering, claim)
		if claim.Said.After(latest[claim.Origin]) {
			latest[claim.Origin] = claim.Said
		}
	}
	// A document uploaded on its own and the one sent with the inventory both
	// speak for the build. Where both cover a place, the one said more
	// recently is the build's word: a revision uploaded on its own replaces
	// what came with the inventory, and a later upload replaces the revision.
	stale := ""
	if _, both := latest[Published]; both {
		if _, sent := latest[string(sbom.FromStatement)]; sent {
			stale = Published
			if latest[Published].After(latest[string(sbom.FromStatement)]) {
				stale = string(sbom.FromStatement)
			}
		}
	}

	var found, informing *int64
	for _, claim := range covering {
		if claim.Origin == stale {
			continue
		}
		id := claim.ID
		if !claim.suppresses() {
			if informing == nil {
				informing = &id
			}
			continue
		}
		if claim.Origin == string(sbom.FromPedigree) {
			return &id, &id
		}
		if found == nil {
			// The first in a stable order, so the answer does not move
			// between runs.
			found = &id
		}
	}
	if found != nil {
		return found, found
	}
	return nil, informing
}

// claimsByName is a build's claims by the issue each names, normalized.
type claimsByName map[string][]int

// indexClaims puts each claim under the name it argues about, once per apply
// rather than once per place a reported issue occupies.
func indexClaims(claims []Claim) claimsByName {
	index := claimsByName{}
	for i, claim := range claims {
		name := normalize(claim.Vulnerability)
		index[name] = append(index[name], i)
	}
	return index
}

// naming is the claims naming an issue by its identifier or any alias, in the
// order the claims were read.
func (index claimsByName) naming(claims []Claim, issue Named) []Claim {
	var at []int
	seen := map[string]bool{}
	for _, name := range append([]string{issue.Identifier}, issue.Aliases...) {
		name = normalize(name)
		if seen[name] {
			continue
		}
		seen[name] = true
		at = append(at, index[name]...)
	}
	sort.Ints(at)
	out := make([]Claim, 0, len(at))
	for _, i := range at {
		out = append(out, claims[i])
	}
	return out
}
