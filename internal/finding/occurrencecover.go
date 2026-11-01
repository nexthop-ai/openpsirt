// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// OccurrenceCovered is an issue in a component as one product of the build
// pulls it in, where the component's occurrences disagree and every occurrence
// beneath that product agrees.
//
// A VEX document states it naming the consumer as the product and the
// component beneath it: "zlib inside curl 8.5.0: not affected". A reader
// applies such a statement beneath the product it names, so it is made only
// where everything beneath that product was decided the same way.
type OccurrenceCovered struct {
	VulnerabilityID int64
	Identifier      string
	Component       string
	Purl            string
	// Consumer and ConsumerPurl are the product the statement names: the
	// component pulling this one in, by the package identifier the build
	// stated for it.
	Consumer     string
	ConsumerPurl string
	Covering
}

// coveredOccurrence is one open occurrence of an issue, and whether approved,
// live decisions agreeing on one outcome cover it.
type coveredOccurrence struct {
	vulnerabilityID int64
	identifier      string
	componentID     int64
	component       string
	purl            string
	consumerID      int64
	consumer        string
	consumerPurl    string
	covered         bool
	Covering
}

// statedGroup is what one statement about a component is about: an issue, and a
// component by its name and the package identifier the build stated.
type statedGroup struct {
	vulnerabilityID int64
	component       string
	purl            string
}

// coveredAtOccurrences is what a VEX document of one build states occurrence
// by occurrence: the occurrences a decision covers, in components some of whose
// occurrences are open and undecided or decided another way.
//
// An occurrence is stated only where all of these hold:
//
//   - its consumer's package identifier names a version, because a statement
//     naming a product at no version is about every release of it. An occurrence
//     the build holds directly has no consumer, and so no product but the
//     build, which a statement about the whole build names
//
// - every open occurrence of the component beneath the consumer, at any depth,
// is
//
//	covered with the same outcome
//
// Where several occurrences beneath one consumer were decided in separate
// sittings, the earliest decision speaks, as it does for a whole component.
func (s *decidedSets) coveredAtOccurrences(ctx context.Context, db bun.IDB, buildID int64,
	most int) ([]OccurrenceCovered, error) {

	every := s.everyOccurrence()
	if len(every) == 0 {
		return nil, nil
	}
	occurrences, err := occurrenceEdges(ctx, db, buildID, 0)
	if err != nil {
		return nil, err
	}
	children := map[int64][]int64{}
	for child, above := range occurrences {
		for _, consumer := range above {
			children[consumer] = append(children[consumer], child)
		}
	}
	beneath := map[int64]map[int64]bool{}
	under := func(consumer int64) map[int64]bool {
		if held, ok := beneath[consumer]; ok {
			return held
		}
		seen := map[int64]bool{consumer: true}
		queue := append([]int64(nil), children[consumer]...)
		for len(queue) > 0 {
			at := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			if seen[at] {
				continue
			}
			seen[at] = true
			queue = append(queue, children[at]...)
		}
		beneath[consumer] = seen
		return seen
	}

	var out []OccurrenceCovered
	stated := map[[2]any]bool{}
	for g, all := range every {
		wholly := true
		for _, one := range all {
			if !one.covered || one.Outcome != all[0].Outcome {
				wholly = false
				break
			}
		}
		if wholly {
			// One statement about the whole component says it.
			continue
		}
		for _, one := range all {
			if !one.covered ||
				graph.PartsOfPurl(one.consumerPurl).Version == "" ||
				stated[[2]any{g, one.consumerID}] {
				continue
			}
			inside := under(one.consumerID)
			earliest, agreed := one.DecidedBy, true
			for _, other := range all {
				if !inside[other.consumerID] {
					continue
				}
				if !other.covered || other.Outcome != one.Outcome {
					agreed = false
					break
				}
				earliest = min(earliest, other.DecidedBy)
			}
			if !agreed {
				continue
			}
			stated[[2]any{g, one.consumerID}] = true
			out = append(out, OccurrenceCovered{
				VulnerabilityID: one.vulnerabilityID, Identifier: one.identifier,
				Component: one.component, Purl: one.purl,
				Consumer: one.consumer, ConsumerPurl: one.consumerPurl,
				Covering: Covering{Outcome: one.Outcome, DecidedBy: earliest},
			})
			if len(out) > most {
				return out, nil
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Identifier != b.Identifier {
			return a.Identifier < b.Identifier
		}
		if a.Purl != b.Purl {
			return a.Purl < b.Purl
		}
		return a.ConsumerPurl < b.ConsumerPurl
	})
	return out, nil
}

// everyOccurrence is every open occurrence of the issues decided, grouped by
// what one statement is about, with whether each is covered: approved, live
// decisions agreeing on one outcome. A group no decision covers an occurrence
// of states nothing.
func (s *decidedSets) everyOccurrence() map[statedGroup][]coveredOccurrence {
	out := map[statedGroup][]coveredOccurrence{}
	for _, f := range s.findings {
		c := s.components[f.ComponentID]
		g := statedGroup{f.VulnerabilityID, c.Name, c.Purl}
		one := coveredOccurrence{
			vulnerabilityID: f.VulnerabilityID, identifier: s.identifiers[f.VulnerabilityID],
			componentID: f.ComponentID, component: c.Name, purl: c.Purl,
			consumerID: f.ConsumerID,
		}
		if f.ConsumerID != 0 {
			uc := s.components[f.ConsumerID]
			one.consumer, one.consumerPurl = uc.Name, uc.Purl
		}
		if f.decided > 0 {
			one.covered = f.agreed()
			one.Covering = Covering{Outcome: f.least, DecidedBy: f.first}
		}
		out[g] = append(out[g], one)
	}
	return out
}
