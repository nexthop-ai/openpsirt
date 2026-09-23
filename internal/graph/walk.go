// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// depth bounds every recursive walk over a build's edges.
//
// The graphs an inventory describes are containment a few levels deep — the
// deepest route measured in a real image was three steps — so this is not a
// bound on a build, it is a bound on a document in a loop. A cycle in the
// edges would otherwise be walked until the engine gave up, and the engines
// give up differently: one stops at a thousand steps with an error, the
// others do not stop. Bounded here, a cycle costs at most this many steps
// and the component it hides is reported as unplaced, which is what it is.
const depth = 64

// Within is the components at one component and everywhere beneath it in a
// build, each once however many ways it is reached, as a statement for a
// membership test: what the findings list narrows by when asked for
// everything the tree's number counts, so the two agree.
//
// One recursive statement rather than a walk in memory bound back as a list of
// identifiers. The subtree under a build's root is every component in the
// build, and binding six thousand identifiers into a statement was the cost of
// asking for it; the engine walking its own edges is the same set with nothing
// crossing the wire. Bounded on depth and not on rows, and a caller that
// materializes it has to say what it does past a size. The subtree under a
// build's root is every component in the build, so scanning this into a slice
// is unbounded by construction; the two callers that pass it into a subquery
// never hold it.
func Within(db *bun.DB, targetID, componentID int64) *bun.RawQuery {
	return WithinAny(db, targetID, []int64{componentID})
}

// WithinAny is the same for a set of components, in one statement.
//
// One walk per named component was one recursive round trip each, in a Go loop
// over every build of the product — so a rule naming a pattern that matches
// broadly issued tens of thousands of them inside one request. The engine
// walks from every anchor at once instead.
func WithinAny(db bun.IDB, targetID int64, componentIDs []int64) *bun.RawQuery {
	return db.NewRaw(`WITH RECURSIVE "down" AS (
		SELECT n.id AS "node", 0 AS "depth"
		FROM "graph_node" AS "n"
		WHERE n.target_id = ? AND n.closed_scan_id IS NULL AND n.component_id IN (?)
		UNION
		SELECT e.child_id, d.depth + 1
		FROM "down" AS "d" CROSS JOIN "graph_edge" AS "e"
		WHERE e.target_id = ? AND e.closed_scan_id IS NULL AND e.parent_id = d.node
		  AND d.depth < ? AND e.parent_id <> e.child_id
	)
	SELECT DISTINCT n.component_id FROM "down" AS "d" JOIN "graph_node" AS "n" ON n.id = d.node`,
		targetID, bun.List(componentIDs), targetID, depth)
}

// The downward walks are written as `CROSS JOIN ... WHERE` rather than
// `JOIN ... ON`, and the difference is not cosmetic. It is standard SQL and
// an inner join on every engine; on SQLite it is also an instruction about
// order, and the order is the whole cost. Without it the planner put the
// edge table on the outside of the recursive step — the target alone looked
// selective — and scanned every edge in the build once per row of the queue:
// 6.6 s to count what sits under a build's root, 9 s for the tree's first
// screen. With the queue on the outside each step is one index seek, and
// the same two statements take 0.018 s and 0.08 s.

// beneath counts the distinct issues open under each of these components,
// including on it, in one statement.
//
// Worked out when the tree is read rather than stored after a scan. Storing it
// was the first attempt and it is the wrong shape: the number is derived from
// findings, and findings move between scans — something dismissed, something
// assigned, a rating reconsidered. A stored total is right at the moment a
// scan ends and drifts from the screen beside it thereafter, which is a screen
// quoting yesterday's answer with nothing saying so.
//
// Distinct issues, not finding rows. A finding is one issue at one place, and
// a library at thirty-six places with two issues is seventy-two rows — which
// is what a parent reads if it counts findings, where somebody who drilled
// down one path is looking at one place and expects two. The issues open
// against a component are the same at every place it sits, so counting them
// once per component answers per path without a walk per path. And counted
// over distinct components, not summed along edges: a library
// reached by twenty containers is one thing inside each of them. The
// statement says exactly that: the subtree as a set of components, joined to
// the distinct (component, issue) pairs open in the build, counted per start.
// And by severity, in the same statement. A node saying five thousand
// beneath it says nothing about whether any of it matters, which is what
// somebody deciding where to descend is asking. An issue has one rating, so
// the bands partition the distinct issues and their counts sum back to the
// total — one query answers both, and two queries would be two chances for the
// number and its parts to disagree.
func (s *Store) beneath(ctx context.Context, productID, targetID int64,
	visible []access.Visibility, of []int64) (map[int64]map[string]int, error) {

	totals := map[int64]map[string]int{}
	if len(of) == 0 {
		return totals, nil
	}
	var rows []struct {
		ComponentID int64  `bun:"component_id"`
		Band        string `bun:"band"`
		Issues      int    `bun:"issues"`
	}
	err := s.db.NewRaw(`WITH RECURSIVE "down" AS (
		SELECT n.id AS "start", n.id AS "node", 0 AS "depth"
		FROM "graph_node" AS "n"
		WHERE n.target_id = ? AND n.closed_scan_id IS NULL AND n.component_id IN (?)
		UNION
		SELECT d.start, e.child_id, d.depth + 1
		FROM "down" AS "d" CROSS JOIN "graph_edge" AS "e"
		WHERE e.target_id = ? AND e.closed_scan_id IS NULL AND e.parent_id = d.node
		  AND d.depth < ? AND e.parent_id <> e.child_id
	)
	SELECT sn.component_id AS "component_id", p.band AS "band",
	       COUNT(DISTINCT p.vulnerability_id) AS "issues"
	FROM (SELECT DISTINCT d.start, d.node FROM "down" AS "d") AS "w"
	JOIN "graph_node" AS "sn" ON sn.id = w.start
	JOIN "graph_node" AS "n" ON n.id = w.node
	JOIN (SELECT f.component_id AS "component_id", f.vulnerability_id AS "vulnerability_id",
	             `+rating.EffectiveExpr+` AS "band"
	      FROM "finding" AS "f"
	      JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id
	      `+rating.Here+`
	      WHERE f.target_id = ? AND f.closed_at IS NULL AND f.visibility IN (?)
	      GROUP BY f.component_id, f.vulnerability_id, `+rating.EffectiveExpr+`) AS "p"
	  ON p.component_id = n.component_id
	GROUP BY sn.component_id, p.band`,
		targetID, bun.List(of), targetID, depth, productID, targetID, bun.List(visible)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("count what is open beneath each component: %w", err)
	}
	for _, row := range rows {
		// The word as the data has it. Folding a rating nobody recognizes into
		// one word is the reader's question and is done where the answer is
		// shaped: this package cannot import the one that says which words are
		// real without a cycle, and a second copy of that list here is the
		// thing that list exists to prevent.
		if totals[row.ComponentID] == nil {
			totals[row.ComponentID] = map[string]int{}
		}
		totals[row.ComponentID][row.Band] += row.Issues
	}
	return totals, nil
}

// step is one node on a way up from a component, as the database reports it:
// which walk it belongs to, where it is, where it was reached from, and how
// far up it sits.
type step struct {
	Start       int64  `bun:"start"`
	Node        int64  `bun:"node"`
	Via         int64  `bun:"via"`
	Depth       int    `bun:"depth"`
	ComponentID int64  `bun:"component_id"`
	IsRoot      bool   `bun:"is_root"`
	Name        string `bun:"name"`
	Version     string `bun:"version"`
}

// climb reads every way up from each of these components, to the bound, in
// one statement: each row is a node on a route, with the node it was reached
// from, so the routes can be unwound.
//
// The recursive step does not repeat the build, and the two downward walks
// do. That asymmetry is the indexes rather than an omission: those walk on
// `parent_id` and use the index leading on the build, so the build is its
// leading column; this walks on `child_id` and uses the one leading on that,
// which a build predicate cannot help and could push a planner off. The answer
// is the same either way — a node identifier is unique across builds, so an
// edge of another build cannot match a node of this one.
func (s *Store) climb(ctx context.Context, targetID int64, componentIDs []int64) ([]step, error) {
	var rows []step
	err := s.db.NewRaw(`WITH RECURSIVE "up" AS (
		SELECT n.id AS "start", n.id AS "node", n.id AS "via", 0 AS "depth"
		FROM "graph_node" AS "n"
		WHERE n.target_id = ? AND n.closed_scan_id IS NULL AND n.component_id IN (?)
		UNION
		SELECT u.start, e.parent_id, u.node, u.depth + 1
		FROM "up" AS "u" CROSS JOIN "graph_edge" AS "e"
		WHERE e.child_id = u.node AND e.closed_scan_id IS NULL
		  AND u.depth < ? AND e.parent_id <> e.child_id
	)
	SELECT u.start AS "start", u.node AS "node", u.via AS "via", u.depth AS "depth",
	       n.component_id AS "component_id", n.is_root AS "is_root",
	       c.name AS "name", c.version AS "version"
	FROM "up" AS "u"
	JOIN "graph_node" AS "n" ON n.id = u.node
	JOIN "component" AS "c" ON c.id = n.component_id`,
		targetID, bun.List(componentIDs), depth).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("walk up from what is on the page: %w", err)
	}
	return rows, nil
}

// Chains returns the way down to each of these components, root first.
//
// the complete chain on a finding asks a finding to show the complete chain,
// root to component, with the version at each step, because that is where
// somebody judges whether the vulnerable code is reached. The immediate parent
// alone cannot answer it: where a component is reached several ways the parent
// is often the same word twice, and two identical rows are not two answers.
//
// Read as one recursive statement upward from every component asked about,
// rather than every edge in the build read into memory and walked here. The
// first version did the latter, and it was measured at three to eighteen
// milliseconds — true, and a couple of megabytes allocated on the screen
// opened most, scaling with the graph rather than with the page. Upward is the
// cheap direction: a component has few parents and the routes are a handful of
// rows, so the statement returns what is on the way and nothing else.
//
// With a component reached several ways, the shortest way down is the one
// returned. A path is being shown to explain a position rather than to
// enumerate the graph, and the shortest is the one somebody can hold in mind.
// A component the inventory placed nowhere, or one whose every way up runs
// past the bound, has no chain, which is the honest answer.
func (s *Store) Chains(ctx context.Context, subject access.Subject, targetID int64,
	componentIDs []int64) (map[int64][]Step, error) {

	chains := map[int64][]Step{}
	if len(componentIDs) == 0 {
		return chains, nil
	}
	// May they know this build exists, rather than may they read what is open
	// against it. A chain is the way down to a component and carries no
	// finding, and every caller has already narrowed the components it is
	// asking about. Asked as the stronger question, a collaborator holding no
	// role on the product was refused the path to the component their own case
	// sits in — so the finding their grant is for answered as though it were
	// not there.
	if err := s.knowsBuild(ctx, subject, targetID); err != nil {
		return nil, err
	}
	rows, err := s.climb(ctx, targetID, componentIDs)
	if err != nil {
		return nil, err
	}
	return unwind(rows), nil
}

// unwind turns what climb read into one chain per component, root first.
//
// Each route is unwound from the root back down to where it started, a row at
// a time: the row at one depth names the node it was reached from, which is
// the row at the depth below. Where several rows sit at the same node and
// depth they are different routes of the same length, and any one of them is
// the shortest.
//
// Apart from the statement because two callers unwind the same rows: a
// finding's own chain, and the tree the subject's own work hangs from . Two
// copies of this would be two answers to "which way down".
func unwind(rows []step) map[int64][]Step {
	chains := map[int64][]Step{}
	type at struct {
		start, node int64
		depth       int
	}
	reached := map[at]step{}
	roots := map[int64]step{}
	started := map[int64]int64{}
	for _, row := range rows {
		reached[at{row.Start, row.Node, row.Depth}] = row
		if row.Depth == 0 {
			started[row.Start] = row.ComponentID
		}
		if row.IsRoot {
			if held, seen := roots[row.Start]; !seen || row.Depth < held.Depth {
				roots[row.Start] = row
			}
		}
	}
	for start, top := range roots {
		chain := make([]Step, 0, top.Depth+1)
		for row, ok := top, true; ok; row, ok = reached[at{start, row.Via, row.Depth - 1}] {
			chain = append(chain, Step{Name: row.Name, Version: row.Version})
			if row.Depth == 0 {
				break
			}
		}
		chains[started[start]] = chain
	}
	return chains
}
