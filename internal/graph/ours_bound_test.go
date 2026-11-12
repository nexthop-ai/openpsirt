// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"fmt"
	"testing"

	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// holdEverything hands every open finding in the fixture's build to party,
// written directly: what is pinned is the tree over what they hold, not how
// they came to hold it.
func holdEverything(t *testing.T, f *fixture, party int64) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Table("finding").
		Set(`"assigned_to" = ?`, party).
		Where(`"build_id" = ?`, f.buildID).
		Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// The tree seen upward assembles over at most its bound of components, says it
// is incomplete past that and complete at it, and draws a component nothing
// pulls in directly under the root, where the tree draws it.
func TestTheTreeSeenUpwardSaysWhenItIsIncomplete(t *testing.T) {
	// The bound a store is given here, far below the default, so the test
	// writes tens of findings and not thousands.
	const bound = 50
	each(t, func(t *testing.T, f *fixture) {
		orphan := at("orphan", "1")
		snap := graph.Snapshot{Root: root, Components: []graph.Described{orphan}}
		var reported []finding.Reported
		hit := func(id string, component graph.Described) {
			reported = append(reported, finding.Reported{
				Issue: finding.Named{Identifier: id, Severity: "high"}, Component: component,
			})
		}
		// The orphan holds two issues, so it ranks first and is inside the
		// bound whatever else is cut.
		hit("CVE-2026-0001", orphan)
		hit("CVE-2026-0002", orphan)
		// One more component than the bound, each holding one issue.
		for i := range bound {
			lib := at(fmt.Sprintf("lib%04d", i), "1")
			snap.Components = append(snap.Components, lib)
			snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: lib})
			hit(fmt.Sprintf("CVE-2026-%d", 10000+i), lib)
		}
		if _, err := fixtures.ApplyGraph(t.Context(), f.db, f.buildID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		f.report(t, reported...)
		const party = 81
		holdEverything(t, f, party)
		holder := access.NewPerson(2, "holder", false,
			map[int64][]access.Role{*f.scope.ProductID: {access.PublicRead}}, party)

		rows, complete, err := f.store.AssemblingAtMost(bound).Ours(t.Context(), holder, f.buildID)
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			t.Error("a tree over more components than it assembles read as complete")
		}
		// The root, the components it kept below it, and the orphan.
		if len(rows) != bound+1 {
			t.Fatalf("the tree drew %d nodes, want the root and %d components", len(rows), bound)
		}
		var held *graph.Upward
		for i := range rows {
			if rows[i].Component == orphan.Name {
				held = &rows[i]
			}
		}
		if held == nil || !held.Placed || held.Depth != 1 {
			t.Fatalf("the orphan is drawn as %+v, want it placed directly under the root", held)
		}
		if held.Findings != 2 || held.Beneath != 2 {
			t.Errorf("the orphan reads %d on itself and %d beneath, want 2 and 2", held.Findings, held.Beneath)
		}

		// Holding exactly as many components as the bound, and holding fewer
		// than the default's, are both a complete tree.
		for name, store := range map[string]*graph.Store{
			"at the bound": f.store.AssemblingAtMost(bound + 1), "the default": f.store,
		} {
			rows, complete, err := store.Ours(t.Context(), holder, f.buildID)
			if err != nil {
				t.Fatal(err)
			}
			if !complete || len(rows) != bound+2 {
				t.Errorf("%s, the tree over every component held reads complete %v with %d nodes, want true and %d",
					name, complete, len(rows), bound+2)
			}
		}
	})
}

// A build nothing has been applied to has no root and nothing beneath it, and
// says so rather than refusing.
func TestABuildWithNoInventoryHasNoRoot(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		top, kids, err := f.store.Roots(t.Context(), everyone(f), f.buildID)
		if err != nil {
			t.Fatal(err)
		}
		if top != nil || len(kids) != 0 {
			t.Errorf("a build with no inventory reads root %+v and %d children", top, len(kids))
		}
	})
}
