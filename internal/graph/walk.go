// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"slices"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
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
func Within(db *bun.DB, buildID, componentID int64) *bun.RawQuery {
	return WithinAny(db, buildID, []int64{componentID}, true)
}

// WithinAny is the same for a set of components, in one statement.
//
// One walk per named component was one recursive round trip each, in a Go loop
// over every build of the product — so a rule naming a pattern that matches
// broadly issued tens of thousands of them inside one request. The engine
// walks from every anchor at once instead.
//
// FromRoot says the starts may hold the build's root (RootAmong), and only
// then does the walk also start from every component nothing pulls in, the
// tree's placement of them (§ unplacedSeeds). The branch is left out
// otherwise, since MySQL and MariaDB price it at every node of the build: on
// MySQL 8.4, beneath a leaf package after 52 weekly rescans, a burndown read
// in 1,034 ms with it and 22 ms without.
func WithinAny(db bun.IDB, buildID int64, componentIDs []int64, fromRoot bool) *bun.RawQuery {
	return db.NewRaw(downWalk(false, fromRoot)+
		`SELECT DISTINCT "n"."component_id" FROM "down" AS "d" JOIN "graph_node" AS "n" ON "n"."id" = "d"."node"`,
		downArgs(buildID, componentIDs, fromRoot)...)
}

// downWalk is the recursive statement "down" both downward walks run over a
// build's live edges, so the count beneath a component and the list it opens
// take the same steps. It starts from every live node of the components asked
// about and, with fromRoot, from every component nothing pulls in as well
// (§ unplacedSeeds). With started, each row also carries the node its walk
// began at as "start". downArgs binds it.
//
// No depth in the rows. With one, the union keeps a node once per depth it is
// reached at, and a node reached along many paths is walked again from each:
// under one real product's root, 1,612,405 rows for 43,904 pairs, 9.0 s
// against 0.19 s, and for the list alone 167,785 rows for 10,045 components,
// 0.81 s against 0.10 s. Without one, a row already reached is not added
// again, which is also what ends a cycle.
func downWalk(started, fromRoot bool) string {
	start, rootStart, carried, kept := "", "", "", ""
	if started {
		start, rootStart, carried, kept = `"n"."id" AS "start", `, `"rn"."id", `, `"seed"."start", `, `"d"."start", `
	}
	seeds := `SELECT ` + start + `"n"."id" AS "node"
			FROM "graph_node" AS "n"
			WHERE "n"."build_id" = ? AND "n"."closed_scan_id" IS NULL AND "n"."component_id" IN (?)`
	if fromRoot {
		seeds += `
			UNION ALL
			SELECT ` + rootStart + `"fn"."id" FROM "graph_node" AS "rn" CROSS JOIN "graph_node" AS "fn"
			WHERE ` + unplacedSeeds
	}
	return `WITH RECURSIVE "down" AS (
		SELECT ` + carried + `"seed"."node" FROM (` + seeds + `) AS "seed"
		UNION
		SELECT ` + kept + `"e"."child_id"
		FROM "down" AS "d" CROSS JOIN "graph_edge" AS "e"
		WHERE "e"."build_id" = ? AND "e"."closed_scan_id" IS NULL AND "e"."parent_id" = "d"."node"
		  AND "e"."parent_id" <> "e"."child_id"
	)
	`
}

// downArgs binds downWalk, in the order it writes its placeholders.
func downArgs(buildID int64, of []int64, fromRoot bool) []any {
	args := []any{buildID, bun.List(of)}
	if fromRoot {
		args = append(args, buildID, true, bun.List(of), false)
	}
	return append(args, buildID)
}

// RootAmong says whether one of these components is the live root of a build:
// whether a walk from them starts from what nothing pulls in as well.
func RootAmong(ctx context.Context, db bun.IDB, buildID int64, componentIDs []int64) (bool, error) {
	if len(componentIDs) == 0 {
		return false, nil
	}
	found, err := db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, true).
		Where(`"n"."component_id" IN (?)`, bun.List(componentIDs)).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("ask whether build %d's root is among components %v: %w", buildID, componentIDs, err)
	}
	return found, nil
}

// unplacedSeeds joins a build's root, where it is among the components a walk
// starts from, to every live component of the build nothing pulls in, as "rn"
// and "fn". It binds the build, true, the starts and false.
//
// A component no edge reaches sits directly under the root: the tree draws it
// there, and every walk beneath the root reaches it and what it pulls in, so a
// count beneath the root and the list it opens agree with the tree's. A
// source repository a SONiC inventory names is one.
const unplacedSeeds = `"rn"."build_id" = ? AND "rn"."closed_scan_id" IS NULL AND "rn"."is_root" = ?
			  AND "rn"."component_id" IN (?)
			  AND "fn"."build_id" = "rn"."build_id" AND "fn"."closed_scan_id" IS NULL AND "fn"."is_root" = ?
			  AND ` + orphaned

// Replaced is the components a build held and holds no longer, each with the
// live components of the build carrying its name in its ecosystem, as the build
// stated each. A finding keeps the component it opened on, so a rescan at a new
// version replaces the component and not the finding, and what was found on the
// old version is counted wherever the present one sits. A component no live one
// names is left out.
//
// The ecosystem is the type its package identifier names: an npm package and a
// Python one of one name are different software. Where either side names no
// type, the name alone matches.
//
// Two reads of the build's own nodes, on the index the build leads, matched by
// name here. Joined to the live nodes by name in one statement, MySQL 8.4 probes
// every component of each name in the deployment, so the read grows with every
// build sharing a name (`design-docs/analytics-measurements.md` § Trend beneath
// a replaced version).
func Replaced(ctx context.Context, db bun.IDB, buildID int64) (map[int64][]int64, error) {
	type named struct {
		Component int64  `bun:"component_id"`
		Name      string `bun:"name_folded"`
		Opened    int64  `bun:"opened_scan_id"`
		Node      int64  `bun:"id"`
		Purl      string `bun:"purl"`
	}
	read := func(live bool) ([]named, error) {
		var rows []named
		q := db.NewSelect().TableExpr(`"graph_node" AS "n"`).
			Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
			ColumnExpr(`"n"."component_id", `+NodeFolded("n", "c")+` AS "name_folded", "c"."purl"`).
			Where(`"n"."build_id" = ?`, buildID).
			Distinct()
		if live {
			q = q.Where(`"n"."closed_scan_id" IS NULL`)
		} else {
			// Oldest first, so the name the build last stated for a
			// component it held under two is the one kept below, as
			// BuildFolded reads it.
			q = q.ColumnExpr(`"n"."opened_scan_id", "n"."id"`).
				Where(`"n"."closed_scan_id" IS NOT NULL`).
				OrderExpr(`"n"."opened_scan_id", "n"."id"`)
		}
		if err := q.Scan(ctx, &rows); err != nil {
			return nil, err
		}
		return rows, nil
	}
	held, err := read(true)
	if err != nil {
		return nil, fmt.Errorf("read the components build %d holds: %w", buildID, err)
	}
	closed, err := read(false)
	if err != nil {
		return nil, fmt.Errorf("read the components build %d held: %w", buildID, err)
	}
	type typed struct {
		Component int64
		Ecosystem string
	}
	live := map[int64]bool{}
	byName := map[string][]typed{}
	for _, row := range held {
		live[row.Component] = true
		byName[row.Name] = append(byName[row.Name], typed{row.Component, EcosystemOf(row.Purl)})
	}
	out := map[int64][]int64{}
	last := map[int64]named{}
	for _, row := range closed {
		if !live[row.Component] {
			last[row.Component] = row
		}
	}
	for component, row := range last {
		ecosystem := EcosystemOf(row.Purl)
		var same []int64
		for _, namesake := range byName[row.Name] {
			if ecosystem == "" || namesake.Ecosystem == "" || namesake.Ecosystem == ecosystem {
				same = append(same, namesake.Component)
			}
		}
		if len(same) > 0 {
			out[component] = same
		}
	}
	return out, nil
}

// WithinAnd is WithinAny from the starts with the components also added, in one statement whose
// answer a caller tests membership in once: the walk's answer and the
// components named, united inside a derived table. Each form measured in its
// place was slow beneath some component on some engine
// (`design-docs/analytics-measurements.md` § Trend beneath a replaced version):
// two membership tests joined by OR, which MySQL and MariaDB never make a
// semi-join and answer by reading every finding of the build; the components
// named beside the walk in its last step; and the components named as a second
// start of the walk.
func WithinAnd(db bun.IDB, buildID int64, starts, also []int64, fromRoot bool) *bun.RawQuery {
	if len(also) == 0 {
		return WithinAny(db, buildID, starts, fromRoot)
	}
	return db.NewRaw(`SELECT "u"."component_id" FROM (?
	UNION
	SELECT "c"."id" FROM "component" AS "c" WHERE "c"."id" IN (?)) AS "u"`,
		WithinAny(db, buildID, starts, fromRoot), bun.List(also))
}

// The downward walks are written as `CROSS JOIN ... WHERE` rather than
// `JOIN ... ON`, and the difference is not cosmetic. It is standard SQL and
// an inner join on every engine; on SQLite it is also an instruction about
// order, and the order is the whole cost. Without it the planner put the
// edge table on the outside of the recursive step — the build alone looked
// selective — and scanned every edge in the build once per row of the queue:
// 6.6 s to count what sits under a build's root, 9 s for the tree's first
// screen. With the queue on the outside each step is one index seek, and
// the same two statements take 0.018 s and 0.08 s.

// reaching is one component a walk started from, and one it reached.
type reaching struct {
	Start   int64 `bun:"start"`
	Reached int64 `bun:"reached"`
}

// reach walks beneath each of these components in one statement, answering
// every component each one reaches, itself included.
func (s *Store) reach(ctx context.Context, buildID int64, of []int64) ([]reaching, error) {
	if len(of) == 0 {
		return nil, nil
	}
	// Every start is walked from itself, and the root from every component
	// nothing pulls in as well (§ unplacedSeeds), so the root's count is the
	// whole build's in the same walk as everything else being counted. The
	// branch is written only where the root is a start, as in WithinAny.
	fromRoot, err := RootAmong(ctx, s.db, buildID, of)
	if err != nil {
		return nil, err
	}
	var reached []reaching
	err = s.db.NewRaw(downWalk(true, fromRoot)+`SELECT DISTINCT "sn"."component_id" AS "start", "n"."component_id" AS "reached"
	FROM "down" AS "d"
	JOIN "graph_node" AS "sn" ON "sn"."id" = "d"."start"
	JOIN "graph_node" AS "n" ON "n"."id" = "d"."node"`, downArgs(buildID, of, fromRoot)...).
		Scan(ctx, &reached)
	if err != nil {
		return nil, fmt.Errorf("walk beneath each component: %w", err)
	}
	return reached, nil
}

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
// Distinct issues, not finding rows. A finding is one issue at one occurrence, and
// a library at thirty-six occurrences with two issues is seventy-two rows — which
// is what a parent reads if it counts findings, where somebody who drilled
// down one path is looking at one occurrence and expects two. The issues open
// against a component are the same at every occurrence it sits at, so counting them
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
func (s *Store) beneath(ctx context.Context, productID, buildID int64,
	visible []access.Visibility, reached []reaching) (map[int64]map[string]int, error) {

	totals := map[int64]map[string]int{}
	// The occurrences are grouped to one row per issue on a component before the
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
	kinds, kindArgs := kind.Inventory.Where(`"f"."kind"`)
	args := append([]any{buildID, bun.List(visible)}, kindArgs...)
	args = append(args, bun.List(all), productID)
	err := s.db.NewRaw(`SELECT "g"."component_id" AS "component_id", "g"."vulnerability_id" AS "vulnerability_id",
	       `+rating.EffectiveExpr+` AS "band"
	FROM (SELECT "f"."component_id" AS "component_id", "f"."vulnerability_id" AS "vulnerability_id"
	      FROM "finding" AS "f"
	      WHERE "f"."build_id" = ? AND "f"."closed_at" IS NULL AND "f"."visibility" IN (?)
	        AND `+kinds+` AND "f"."component_id" IN (?)
	      GROUP BY "f"."component_id", "f"."vulnerability_id") AS "g"
	JOIN "vulnerability" AS "v" ON "v"."id" = "g"."vulnerability_id"
	`+rating.Here, args...).
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
func (s *Store) climb(ctx context.Context, buildID int64, componentIDs []int64) (region, error) {
	var rows []rise
	err := s.db.NewRaw(`WITH RECURSIVE "up" AS (
		SELECT "n"."id" AS "node"
		FROM "graph_node" AS "n"
		WHERE "n"."build_id" = ? AND "n"."closed_scan_id" IS NULL AND "n"."component_id" IN (?)
		UNION
		SELECT "e"."parent_id"
		FROM "up" AS "u" CROSS JOIN "graph_edge" AS "e"
		WHERE "e"."child_id" = "u"."node" AND "e"."closed_scan_id" IS NULL AND "e"."parent_id" <> "e"."child_id"
	)
	SELECT "u"."node" AS "node", "e"."parent_id" AS "parent",
	       "n"."component_id" AS "component_id", "n"."is_root" AS "is_root",
	       `+NodeName("n", "c")+` AS "name", `+NodeVersion("n", "c")+` AS "version", "c"."purl" AS "purl"
	FROM "up" AS "u"
	JOIN "graph_node" AS "n" ON "n"."id" = "u"."node"
	JOIN "component" AS "c" ON "c"."id" = "n"."component_id"
	LEFT JOIN "graph_edge" AS "e"
	  ON "e"."child_id" = "u"."node" AND "e"."closed_scan_id" IS NULL AND "e"."parent_id" <> "e"."child_id"`,
		buildID, bun.List(componentIDs)).
		Scan(ctx, &rows)
	if err != nil {
		return region{}, fmt.Errorf("walk up from what is on the page: %w", err)
	}
	if rows, err = s.underRoot(ctx, buildID, rows); err != nil {
		return region{}, err
	}
	return regionOf(rows, componentIDs), nil
}

// underRoot hangs every node climb reached that nothing pulls in from the
// build's root, the place the tree and every walk beneath the root give it
// (§ unplacedSeeds), so its chain is the root and itself.
func (s *Store) underRoot(ctx context.Context, buildID int64, rows []rise) ([]rise, error) {
	parented := map[int64]bool{}
	for _, row := range rows {
		if row.Parent != nil {
			parented[row.Node] = true
		}
	}
	var loose []rise
	for _, row := range rows {
		if !row.IsRoot && !parented[row.Node] {
			loose = append(loose, row)
		}
	}
	if len(loose) == 0 {
		return rows, nil
	}
	var root []rise
	if err := s.db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`"n"."id" AS "node", "n"."component_id" AS "component_id", "n"."is_root" AS "is_root"`).
		ColumnExpr(NodeName("n", "c")+` AS "name", `+NodeVersion("n", "c")+` AS "version", "c"."purl" AS "purl"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, true).
		Scan(ctx, &root); err != nil {
		return nil, fmt.Errorf("read the root of build %d: %w", buildID, err)
	}
	if len(root) == 0 {
		return rows, nil
	}
	rows = append(rows, root[0])
	for _, row := range loose {
		row.Parent = &root[0].Node
		rows = append(rows, row)
	}
	return rows, nil
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
// inside a product is evidence where the product is above the occurrence, and
// nowhere else. Read through the same walk the chains are, to the same bound.
func (s *Store) Above(ctx context.Context, subject access.Subject, buildID,
	componentID int64) ([]Component, error) {

	if err := s.knowsBuild(ctx, subject, buildID); err != nil {
		return nil, err
	}
	climbed, err := s.climb(ctx, buildID, []int64{componentID})
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
	if err := s.db.NewSelect().Model(&above).Where(`"c"."id" IN (?)`, bun.List(ids)).
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
// A component nothing pulls in hangs from the root, so its chain is the root
// and itself (§ unplacedSeeds). One whose every way up runs past the bound
// has no chain, which is the honest answer.
func (s *Store) Chains(ctx context.Context, subject access.Subject, buildID int64,
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
	if err := s.knowsBuild(ctx, subject, buildID); err != nil {
		return nil, err
	}
	climbed, err := s.climb(ctx, buildID, componentIDs)
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

// codeCounts is the open code findings on each component counted, and on it
// and everything it reaches, each once.
type codeCounts struct {
	on      map[int64]int
	beneath map[int64]int
}

// codeBeneath counts the open code findings on and beneath each start of a
// walk, by the components it reached, where the store counts code findings.
// Nil where it does not.
//
// The build's root is the build itself: on it are the code findings on every
// component that was ever its root, and beneath it every code finding the
// build holds, as the queue beneath the root lists them. A code finding keeps
// the component it opened on, so one on a root a rescan replaced is still on
// the build, and the walk from the present root reaches no closed node.
func (s *Store) codeBeneath(ctx context.Context, buildID int64, reached []reaching) (*codeCounts, error) {
	if s.code == nil {
		return nil, nil
	}
	out := &codeCounts{on: map[int64]int{}, beneath: map[int64]int{}}
	// Nothing reached is nothing to count; the read below takes no
	// components as the whole build.
	if len(reached) == 0 {
		return out, nil
	}
	root, roots, err := s.rootsOf(ctx, buildID)
	if err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	var all []int64
	rooted := false
	for _, row := range reached {
		rooted = rooted || row.Start == root
		if !seen[row.Reached] {
			seen[row.Reached] = true
			all = append(all, row.Reached)
		}
	}
	// Asked for the root, every component of the build is read, which holds
	// everything any other start reaches.
	if rooted {
		all = nil
	}
	on, err := s.code(ctx, buildID, all)
	if err != nil {
		return nil, err
	}
	under := map[int64]map[string]bool{}
	gather := func(start int64, occurrences []string) {
		if len(occurrences) == 0 {
			return
		}
		if under[start] == nil {
			under[start] = map[string]bool{}
		}
		for _, occurrence := range occurrences {
			under[start][occurrence] = true
		}
	}
	for _, row := range reached {
		if row.Start == root {
			continue
		}
		if row.Start == row.Reached {
			out.on[row.Start] = len(on[row.Start])
		}
		gather(row.Start, on[row.Reached])
	}
	if rooted {
		placed := map[string]bool{}
		for _, id := range roots {
			for _, occurrence := range on[id] {
				placed[occurrence] = true
			}
		}
		out.on[root] = len(placed)
		for _, occurrences := range on {
			gather(root, occurrences)
		}
	}
	for start, occurrences := range under {
		out.beneath[start] = len(occurrences)
	}
	return out, nil
}

// withReplaced is reached with each replaced component reached from every
// start reaching a live component of its name.
func withReplaced(reached []reaching, replaced map[int64][]int64) []reaching {
	if len(replaced) == 0 {
		return reached
	}
	named := map[int64][]int64{}
	for old, live := range replaced {
		for _, l := range live {
			named[l] = append(named[l], old)
		}
	}
	out := slices.Clone(reached)
	added := map[reaching]bool{}
	for _, row := range reached {
		for _, old := range named[row.Reached] {
			if pair := (reaching{Start: row.Start, Reached: old}); !added[pair] {
				added[pair] = true
				out = append(out, pair)
			}
		}
	}
	return out
}

// ReplacedWithin is the components of replaced whose name a component at one
// of the starts or anywhere under one carries, sorted. A finding on one is
// beneath the component as one on its live namesake is.
//
// Answered as values and named beside the walk rather than matched to it by
// name in the walk's own statement: on MySQL 8.4 the trend beneath the bench
// kernel took 1.72 s that way.
func ReplacedWithin(ctx context.Context, db bun.IDB, buildID int64, starts []int64,
	replaced map[int64][]int64) ([]int64, error) {

	if len(replaced) == 0 {
		return nil, nil
	}
	seen := map[int64]bool{}
	var namesakes []int64
	for _, live := range replaced {
		for _, l := range live {
			if !seen[l] {
				seen[l] = true
				namesakes = append(namesakes, l)
			}
		}
	}
	fromRoot, err := RootAmong(ctx, db, buildID, starts)
	if err != nil {
		return nil, err
	}
	var reached []int64
	if err := db.NewSelect().TableExpr(`(?) AS "w"`, WithinAny(db, buildID, starts, fromRoot)).
		ColumnExpr(`"w"."component_id"`).
		Where(`"w"."component_id" IN (?)`, bun.List(namesakes)).
		Scan(ctx, &reached); err != nil {
		return nil, fmt.Errorf("read which replaced components are beneath components %v of build %d: %w",
			starts, buildID, err)
	}
	return ReplacedAmong(replaced, reached), nil
}

// ReplacedAmong is the components of replaced whose name a component of
// reached carries, sorted.
func ReplacedAmong(replaced map[int64][]int64, reached []int64) []int64 {
	in := map[int64]bool{}
	for _, id := range reached {
		in[id] = true
	}
	var out []int64
	for old, live := range replaced {
		if slices.ContainsFunc(live, func(l int64) bool { return in[l] }) {
			out = append(out, old)
		}
	}
	slices.Sort(out)
	return out
}

// Reaching is, for each of these components, every component of the build at
// it or beneath it, in one walk: the tree's own walk, for a list that counts
// beneath several components at once.
func Reaching(ctx context.Context, db bun.IDB, buildID int64, starts []int64) (map[int64][]int64, error) {
	reached, err := (&Store{db: db}).reach(ctx, buildID, starts)
	if err != nil {
		return nil, err
	}
	out := make(map[int64][]int64, len(starts))
	for _, r := range reached {
		out[r.Start] = append(out[r.Start], r.Reached)
	}
	return out, nil
}
