// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"slices"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// depth bounds how far up a route is drawn: the way down to a component on a
// finding, and what sits above it.
//
// The graphs an inventory describes are containment a few levels deep — the
// deepest route measured in a real image was three steps — so this is not a
// bound on a build. A component more than this many steps below every root is
// reported as unplaced, which is what a document in a loop leaves it as.
//
// No walk carries a depth in its rows, because carrying one multiplies them:
// the union adds a node once and that ends a cycle. The walks run as far as
// the edges go, which is why the connection lifts the bound on rounds on the
// two engines that have one, and the bound is applied to the routes drawn
// from what they read.
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
// crossing the wire. Not bounded on rows, and a caller that materializes it
// has to say what it does past a size. The subtree under a
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
	// No depth in the rows, for the reason the count beneath carries none:
	// 167,785 rows for 10,045 components under one real product, 0.81 s
	// against 0.10 s, and the union ends a cycle on its own.
	return db.NewRaw(`WITH RECURSIVE "down" AS (
		SELECT n.id AS "node"
		FROM "graph_node" AS "n"
		WHERE n.target_id = ? AND n.closed_scan_id IS NULL AND n.component_id IN (?)
		UNION
		SELECT e.child_id
		FROM "down" AS "d" CROSS JOIN "graph_edge" AS "e"
		WHERE e.target_id = ? AND e.closed_scan_id IS NULL AND e.parent_id = d.node
		  AND e.parent_id <> e.child_id
	)
	SELECT DISTINCT n.component_id FROM "down" AS "d" JOIN "graph_node" AS "n" ON n.id = d.node`,
		targetID, bun.List(componentIDs), targetID)
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
// including on it.
//
// Worked out when the tree is read rather than stored after a scan. Storing it
// is the wrong shape: the number is derived from findings, and findings move
// between scans — something dismissed, something assigned, a rating
// reconsidered. A stored total is right at the moment a scan ends and drifts
// from the screen beside it thereafter, which is a screen quoting yesterday's
// answer with nothing saying so.
//
// Distinct issues, not finding rows. A finding is one issue at one place, and
// a library at thirty-six places with two issues is seventy-two rows — which
// is what a parent reads if it counts findings, where somebody who drilled
// down one path is looking at one place and expects two. The issues open
// against a component are the same at every place it sits, so counting them
// once per component answers per path without a walk per path. And counted
// over distinct components, not summed along edges: a library reached by
// twenty containers is one thing inside each of them.
//
// Two statements: the walk, which says which components each start reaches,
// and the issues open on the components reached, each once per component,
// named as values. The union per start is taken here. Joined in the database,
// every start reaching a large component carries that component's issues
// again: the bench kernel's 45 parents make 302,269 rows to sort and count for
// 270 answers, 345 ms on PostgreSQL, where the two statements return 5,331 and
// 10,769 rows. The second walks nothing: walked again to restrict
// the findings, it repeated the first statement's work, and SQLite read every
// node in the database to match the walk's — 343 ms for the issues beneath
// the measurement kernel's 34 consumers, against 208 ms named as values. On
// the statistics a large scan leaves behind, reading what is around that
// kernel took 4.2 s on PostgreSQL and 14.2 s on MariaDB, against 0.28 s and
// 0.14 s.
//
// And by severity. A node saying five thousand beneath it says nothing about
// whether any of it matters, which is what somebody deciding where to descend
// is asking. An issue has one rating, so the bands partition the distinct
// issues; the total is summed from them by the caller, so the number and its
// parts cannot disagree.
func (s *Store) beneath(ctx context.Context, productID, targetID int64,
	visible []access.Visibility, of []int64, adopt adoption) (map[int64]map[string]int, error) {

	totals := map[int64]map[string]int{}
	if len(of) == 0 {
		return totals, nil
	}
	// Every start is walked from itself. An adoption walks the adopted
	// components as though from the one adopting them, so the adopter's count
	// is its own subtree and theirs as one set, in the same walk as everything
	// else being counted.
	seeds := `SELECT n.id AS "start", n.id AS "node"
		FROM "graph_node" AS "n"
		WHERE n.target_id = ? AND n.closed_scan_id IS NULL AND n.component_id IN (?)`
	walkArgs := []any{targetID, bun.List(of)}
	if len(adopt.IDs) > 0 {
		seeds += `
		UNION ALL
		SELECT bn.id, n.id
		FROM "graph_node" AS "bn"
		JOIN "graph_node" AS "n" ON n.target_id = bn.target_id
		WHERE bn.target_id = ? AND bn.closed_scan_id IS NULL AND bn.component_id = ?
		  AND n.closed_scan_id IS NULL AND n.component_id IN (?)`
		walkArgs = append(walkArgs, targetID, adopt.By, bun.List(adopt.IDs))
	}
	walkArgs = append(walkArgs, targetID)
	// No depth in the rows. With one, the union keeps a node once per depth
	// it is reached at, and a node reached along many paths is walked again
	// from each: 1,612,405 rows for 43,904 pairs under one real product's
	// root, 9.0 s against 0.19 s. Without one, a pair already reached is not
	// added again, which is also what ends a cycle.
	walk := `WITH RECURSIVE "down" AS (
		SELECT "seed"."start", "seed"."node" FROM (` + seeds + `) AS "seed"
		UNION
		SELECT d.start, e.child_id
		FROM "down" AS "d" CROSS JOIN "graph_edge" AS "e"
		WHERE e.target_id = ? AND e.closed_scan_id IS NULL AND e.parent_id = d.node
		  AND e.parent_id <> e.child_id
	)
	`

	var reached []struct {
		Start   int64 `bun:"start"`
		Reached int64 `bun:"reached"`
	}
	err := s.db.NewRaw(walk+`SELECT DISTINCT sn.component_id AS "start", n.component_id AS "reached"
	FROM "down" AS "d"
	JOIN "graph_node" AS "sn" ON sn.id = d.start
	JOIN "graph_node" AS "n" ON n.id = d.node`, walkArgs...).
		Scan(ctx, &reached)
	if err != nil {
		return nil, fmt.Errorf("walk beneath each component: %w", err)
	}

	// The places are grouped to one row per issue on a component before the
	// rating is joined, and only on the components the walk reaches.
	var open []struct {
		ComponentID     int64  `bun:"component_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Band            string `bun:"band"`
	}
	seen := map[int64]bool{}
	var all []int64
	for _, row := range reached {
		if !seen[row.Reached] {
			seen[row.Reached] = true
			all = append(all, row.Reached)
		}
	}
	if len(all) == 0 {
		return totals, nil
	}
	err = s.db.NewRaw(`SELECT g.component_id AS "component_id", g.vulnerability_id AS "vulnerability_id",
	       `+rating.EffectiveExpr+` AS "band"
	FROM (SELECT f.component_id AS "component_id", f.vulnerability_id AS "vulnerability_id"
	      FROM "finding" AS "f"
	      WHERE f.target_id = ? AND f.closed_at IS NULL AND f.visibility IN (?)
	        AND f.component_id IN (?)
	      GROUP BY f.component_id, f.vulnerability_id) AS "g"
	JOIN "vulnerability" AS "v" ON v.id = g.vulnerability_id
	`+rating.Here, targetID, bun.List(visible), bun.List(all), productID).
		Scan(ctx, &open)
	if err != nil {
		return nil, fmt.Errorf("read what is open beneath each component: %w", err)
	}

	type issue struct {
		id   int64
		band string
	}
	on := map[int64][]issue{}
	for _, row := range open {
		on[row.ComponentID] = append(on[row.ComponentID], issue{row.VulnerabilityID, row.Band})
	}
	under := map[int64][]int64{}
	for _, row := range reached {
		under[row.Start] = append(under[row.Start], row.Reached)
	}
	alone := map[int64]map[string]int{}
	for start, components := range under {
		// A start reaching one component that carries anything has that
		// component's issues beneath it, each once already, so no union is
		// taken. 44 of the bench kernel's 45 parents reach the kernel and
		// nothing else carrying an issue, and the union of its 5,655 issues
		// for each of them took 29 ms.
		var carrying []int64
		for _, c := range components {
			if len(on[c]) > 0 {
				carrying = append(carrying, c)
			}
		}
		if len(carrying) == 1 {
			counted, ok := alone[carrying[0]]
			if !ok {
				counted = map[string]int{}
				for _, one := range on[carrying[0]] {
					counted[one.band]++
				}
				alone[carrying[0]] = counted
			}
			bands := make(map[string]int, len(counted))
			for band, n := range counted {
				bands[band] = n
			}
			totals[start] = bands
			continue
		}
		seen := map[issue]bool{}
		for _, c := range carrying {
			for _, one := range on[c] {
				if seen[one] {
					continue
				}
				seen[one] = true
				// The word as the data has it. Folding a rating nobody
				// recognizes into one word is the reader's question and is
				// done where the answer is shaped: this package cannot import
				// the one that says which words are real without a cycle, and
				// a second copy of that list here is the thing that list
				// exists to prevent.
				if totals[start] == nil {
					totals[start] = map[string]int{}
				}
				totals[start][one.band]++
			}
		}
	}
	return totals, nil
}

// adoption names components walked as though the one adopting them pulled
// them in. The zero value adopts nothing.
type adoption struct {
	By  int64
	IDs []int64
}

// rise is one node above the components asked about, as the database
// reports it: where it is, what it is, and one node directly above it. A node
// with several parents is several rows, and one with none — a root, or a
// component the inventory placed nowhere — is one row with no parent.
type rise struct {
	Node        int64  `bun:"node"`
	Parent      *int64 `bun:"parent"`
	ComponentID int64  `bun:"component_id"`
	IsRoot      bool   `bun:"is_root"`
	Name        string `bun:"name"`
	Version     string `bun:"version"`
	Purl        string `bun:"purl"`
}

// region is everything above a set of components in one build: the nodes, and
// the open edges between them, which is what a route up is drawn from.
type region struct {
	at      map[int64]rise
	parents map[int64][]int64
	// starts is the nodes of each component asked about.
	starts map[int64][]int64
}

// climb reads everything above each of these components in one statement:
// every node on any way up, each with the nodes directly above it.
//
// The recursion carries a node and nothing else, so the union adds each node
// once and a cycle ends where it closes. Carrying the start or the depth keeps
// a node once per start and once per length of route to it, which a document
// whose components all depend on each other multiplies by both: thirty such
// components are 870 edges, and with the start and the depth carried one
// start returned 55,060 rows and thirty starts 1,651,800. Here the rows are
// the nodes above the page and the edges among them, however many starts
// there are.
//
// The recursive step does not repeat the build, and the two downward walks
// do. That asymmetry is the indexes rather than an omission: those walk on
// `parent_id` and use the index leading on the build, so the build is its
// leading column; this walks on `child_id` and uses the one leading on that,
// which a build predicate cannot help and could push a planner off. The answer
// is the same either way — a node identifier is unique across builds, so an
// edge of another build cannot match a node of this one.
func (s *Store) climb(ctx context.Context, targetID int64, componentIDs []int64) (region, error) {
	var rows []rise
	err := s.db.NewRaw(`WITH RECURSIVE "up" AS (
		SELECT n.id AS "node"
		FROM "graph_node" AS "n"
		WHERE n.target_id = ? AND n.closed_scan_id IS NULL AND n.component_id IN (?)
		UNION
		SELECT e.parent_id
		FROM "up" AS "u" CROSS JOIN "graph_edge" AS "e"
		WHERE e.child_id = u.node AND e.closed_scan_id IS NULL AND e.parent_id <> e.child_id
	)
	SELECT u.node AS "node", e.parent_id AS "parent",
	       n.component_id AS "component_id", n.is_root AS "is_root",
	       c.name AS "name", c.version AS "version", c.purl AS "purl"
	FROM "up" AS "u"
	JOIN "graph_node" AS "n" ON n.id = u.node
	JOIN "component" AS "c" ON c.id = n.component_id
	LEFT JOIN "graph_edge" AS "e"
	  ON e.child_id = u.node AND e.closed_scan_id IS NULL AND e.parent_id <> e.child_id`,
		targetID, bun.List(componentIDs)).
		Scan(ctx, &rows)
	if err != nil {
		return region{}, fmt.Errorf("walk up from what is on the page: %w", err)
	}
	return regionOf(rows, componentIDs), nil
}

// regionOf indexes what climb read. Parents are held in node order, so the
// route chosen among routes of one length is the same on every read.
func regionOf(rows []rise, componentIDs []int64) region {
	r := region{at: map[int64]rise{}, parents: map[int64][]int64{}, starts: map[int64][]int64{}}
	asked := make(map[int64]bool, len(componentIDs))
	for _, id := range componentIDs {
		asked[id] = true
	}
	for _, row := range rows {
		if _, seen := r.at[row.Node]; !seen {
			r.at[row.Node] = row
			if asked[row.ComponentID] {
				r.starts[row.ComponentID] = append(r.starts[row.ComponentID], row.Node)
			}
		}
		if row.Parent != nil {
			r.parents[row.Node] = append(r.parents[row.Node], *row.Parent)
		}
	}
	for _, held := range r.parents {
		slices.Sort(held)
	}
	for _, held := range r.starts {
		slices.Sort(held)
	}
	return r
}

// above is every node within the bound above these, breadth first, each once.
func (r region) above(starts []int64) []int64 {
	seen := map[int64]bool{}
	for _, node := range starts {
		seen[node] = true
	}
	var out []int64
	level := starts
	for d := 0; d < depth && len(level) > 0; d++ {
		var next []int64
		for _, node := range level {
			for _, parent := range r.parents[node] {
				if seen[parent] {
					continue
				}
				seen[parent] = true
				out = append(out, parent)
				next = append(next, parent)
			}
		}
		level = next
	}
	return out
}

// Above is every component above this one in a build, on any route up to the
// root, the root itself left out.
//
// What places a supplier's statement on a finding: a statement about what sits
// inside a product is evidence where the product is above the place, and
// nowhere else. Read through the same walk the chains are, to the same bound.
func (s *Store) Above(ctx context.Context, subject access.Subject, targetID,
	componentID int64) ([]Component, error) {

	if err := s.knowsBuild(ctx, subject, targetID); err != nil {
		return nil, err
	}
	climbed, err := s.climb(ctx, targetID, []int64{componentID})
	if err != nil {
		return nil, err
	}
	var ids []int64
	seen := map[int64]bool{componentID: true}
	for _, node := range climbed.above(climbed.starts[componentID]) {
		row := climbed.at[node]
		if row.IsRoot || seen[row.ComponentID] {
			continue
		}
		seen[row.ComponentID] = true
		ids = append(ids, row.ComponentID)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var above []Component
	if err := s.db.NewSelect().Model(&above).Where("c.id IN (?)", bun.List(ids)).
		Order("c.id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what sits above it: %w", err)
	}
	return above, nil
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
// rather than every edge in the build read into memory and walked here.
// Reading the whole build was measured at three to eighteen milliseconds and a
// couple of megabytes allocated on the screen opened most, scaling with the
// graph rather than with the page. Upward is the cheap direction: a component
// has few parents, so the statement returns what is on the way and nothing
// else, and the routes are drawn from it here.
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
	climbed, err := s.climb(ctx, targetID, componentIDs)
	if err != nil {
		return nil, err
	}
	return climbed.unwind(), nil
}

// unwind draws one chain per component asked about, root first: the shortest
// way down from a root within the bound.
//
// One breadth-first walk down from every root in the region, over the edges
// climb read, gives each node its distance from the nearest root and the node
// above it on a shortest route. A component's chain is then followed up from
// whichever of its nodes is nearest, so the work is the size of the region
// once rather than once per component. Roots, parents and starts are taken in
// node order, so among routes of one length the same one is drawn every time.
//
// Apart from the statement because two callers unwind the same region: a
// finding's own chain, and the tree the subject's own work hangs from. Two
// copies of this would be two answers to "which way down".
func (r region) unwind() map[int64][]Step {
	children := map[int64][]int64{}
	var roots []int64
	for node, row := range r.at {
		if row.IsRoot {
			roots = append(roots, node)
		}
		for _, parent := range r.parents[node] {
			children[parent] = append(children[parent], node)
		}
	}
	slices.Sort(roots)
	for _, held := range children {
		slices.Sort(held)
	}

	// far is how many steps below a root a node sits, and up the node above
	// it on the way there. A root is its own top.
	far := map[int64]int{}
	up := map[int64]int64{}
	for _, node := range roots {
		far[node] = 0
	}
	level := roots
	for d := 1; d <= depth && len(level) > 0; d++ {
		var next []int64
		for _, node := range level {
			for _, child := range children[node] {
				if _, reached := far[child]; reached {
					continue
				}
				far[child], up[child] = d, node
				next = append(next, child)
			}
		}
		level = next
	}

	chains := map[int64][]Step{}
	for component, starts := range r.starts {
		best, found := int64(0), false
		for _, node := range starts {
			d, reached := far[node]
			if reached && (!found || d < far[best]) {
				best, found = node, true
			}
		}
		if !found {
			continue
		}
		chain := make([]Step, 0, far[best]+1)
		for node := best; ; node = up[node] {
			row := r.at[node]
			chain = append(chain, Step{Name: row.Name, Version: row.Version, Purl: row.Purl})
			if far[node] == 0 {
				break
			}
		}
		slices.Reverse(chain)
		chains[component] = chain
	}
	return chains
}
