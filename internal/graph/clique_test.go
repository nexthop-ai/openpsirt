// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A document whose components all depend on each other is read once per node
// and once per edge, however many components a page climbs from, and the way
// down drawn through it is still the shortest.
func TestAClimbThroughComponentsThatAllDependOnEachOtherReadsEachEdgeOnce(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		const size = 30
		snap := graph.Snapshot{Root: root}
		clique := make([]graph.Described, size)
		for i := range clique {
			clique[i] = at(fmt.Sprintf("c%02d", i), "1")
			snap.Components = append(snap.Components, clique[i])
		}
		for _, parent := range clique {
			for _, child := range clique {
				if parent.Name != child.Name {
					snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: parent, Child: child})
				}
			}
		}
		// The root pulls in the first of them directly, and the last through
		// two more steps, so the last is two steps down one way and three the
		// other.
		x, y := at("x", "1"), at("y", "1")
		snap.Components = append(snap.Components, x, y)
		snap.Dependencies = append(snap.Dependencies,
			graph.Dependency{Parent: root, Child: clique[0]},
			graph.Dependency{Parent: root, Child: x},
			graph.Dependency{Parent: x, Child: y},
			graph.Dependency{Parent: y, Child: clique[size-1]})
		if _, err := f.store.Apply(t.Context(), f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}

		ids := make([]int64, 0, size)
		for _, one := range clique {
			id, err := f.store.ComponentAs(t.Context(), f.targetID, one.Name, graph.Choice{})
			if err != nil {
				t.Fatalf("%s: %v", one.Name, err)
			}
			ids = append(ids, id)
		}

		nodes, edges, err := f.store.Climbed(t.Context(), f.targetID, ids)
		if err != nil {
			t.Fatal(err)
		}
		// Everything above the clique: itself, x, y and the root, and every
		// edge among them, each once.
		wantNodes, wantEdges := size+3, size*(size-1)+4
		if nodes != wantNodes || edges != wantEdges {
			t.Errorf("the climb read %d nodes and %d edges, want %d and %d", nodes, edges, wantNodes, wantEdges)
		}

		chains, err := f.store.Chains(t.Context(), everyone(f), f.targetID, ids)
		if err != nil {
			t.Fatal(err)
		}
		if len(chains) != size {
			t.Fatalf("%d of the %d components have a way down", len(chains), size)
		}
		if got := chain(chains[ids[0]]); got != "sonic > c00" {
			t.Errorf("c00 is reached by %q", got)
		}
		if got := chain(chains[ids[size-1]]); got != "sonic > c00 > c29" {
			t.Errorf("c29 is reached by %q, wanted the shorter of its ways", got)
		}
	})
}
