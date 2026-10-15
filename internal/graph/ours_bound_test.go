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
		Where(`"target_id" = ?`, f.targetID).
		Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// The tree seen upward assembles over at most graph.Ours components, says it
// is incomplete past that, and draws a component the inventory placed nowhere
// at the foot, unplaced.
func TestTheTreeSeenUpwardSaysWhenItIsIncomplete(t *testing.T) {
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
		for i := range graph.Ours {
			lib := at(fmt.Sprintf("lib%04d", i), "1")
			snap.Components = append(snap.Components, lib)
			snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: lib})
			hit(fmt.Sprintf("CVE-2026-%d", 10000+i), lib)
		}
		if _, err := fixtures.ApplyGraph(t.Context(), f.db, f.targetID, f.scan(t), snap); err != nil {
			t.Fatal(err)
		}
		findings := finding.NewStore(f.db.DB)
		run, err := findings.Begin(t.Context(), finding.Run{
			TargetID: f.targetID, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-08-28", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := findings.Apply(t.Context(), f.targetID, run.ID, reported); err != nil {
			t.Fatal(err)
		}
		const party = 81
		holdEverything(t, f, party)
		holder := access.NewPerson(2, "holder", false,
			map[int64][]access.Role{*f.scope.ProductID: {access.PublicRead}}, party)

		rows, complete, err := f.store.Ours(t.Context(), holder, f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			t.Error("a tree over more components than it assembles read as complete")
		}
		// The root, the components it kept below it, and the orphan.
		if len(rows) != graph.Ours+1 {
			t.Fatalf("the tree drew %d nodes, want the root and %d components", len(rows), graph.Ours)
		}
		last := rows[len(rows)-1]
		if last.Component != orphan.Name || last.Placed {
			t.Errorf("the foot of the tree is %+v, want the orphan, unplaced", last)
		}
		if last.Findings != 2 || last.Beneath != 2 {
			t.Errorf("the orphan reads %d on itself and %d beneath, want 2 and 2", last.Findings, last.Beneath)
		}
	})
}

// A build nothing has been applied to has no root and nothing beneath it, and
// says so rather than refusing.
func TestABuildWithNoInventoryHasNoRoot(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		top, kids, err := f.store.Roots(t.Context(), everyone(f), f.targetID)
		if err != nil {
			t.Fatal(err)
		}
		if top != nil || len(kids) != 0 {
			t.Errorf("a build with no inventory reads root %+v and %d children", top, len(kids))
		}
	})
}
