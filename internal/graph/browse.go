// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// Neighbor is one component next to another in the graph.
type Neighbor struct {
	Name    string `bun:"name"`
	Version string `bun:"version"`
	// Findings is how many distinct issues are open against this component
	// itself, and Beneath is that over it and everything under it.
	//
	// Both, because they answer different questions and a container answers
	// zero to the first: it holds no findings of its own, so a tree showing
	// only that says every container is clean while the packages inside them
	// hold thousands. What makes a branch worth opening is what is in it.
	//
	// Issues rather than finding rows. A finding is one issue at one occurrence,
	// and the issues open against a component are the same at every occurrence
	// — so a node drawn beneath one parent is looking at one occurrence, and
	// the count is the issues there, not the rows across every occurrence.
	Findings int `bun:"findings"`
	Beneath  int `bun:"beneath,scanonly"`
	// CodeFindings and CodeBeneath are the open code findings on it, and on
	// it and everything under it with each once, where the store counts code
	// findings. A code finding is at one occurrence, so the union is of
	// occurrences, as the issues' is of issues.
	CodeFindings int `bun:"-"`
	CodeBeneath  int `bun:"-"`
	// BeneathBy is that same number by how the issues were rated. A node
	// saying five thousand beneath it says nothing about whether any of it
	// matters, which is exactly what somebody deciding where to descend is
	// asking. The bands sum to Beneath, because an issue has one rating.
	BeneathBy map[string]int `bun:"-"`
	Children  int            `bun:"children"`
	// Purl is the package identifier, which is where the kind of package it is
	// comes from.
	//
	// The field that tells two components of one name and one version apart. A
	// build ships `opennsl-modules` twice at 15.2.0.0.0.0.0.0, and asking
	// about either by name is refused — rightly, since they are two components
	// — so a screen listing them without this could name neither. The refusal
	// even says which field to send, and nothing offering the choice was
	// saying it.
	//
	// Carried as the identifier rather than as the word, and turned into the
	// word by the one function that knows how, where every other reader of a
	// component does the same.
	Purl string `bun:"purl,scanonly"`
	// ComponentID is what the rollup is worked out from. Read rather than
	// shown.
	ComponentID int64 `bun:"component_id"`
}

// Around reports what sits directly above and below one component in a build.
//
// A neighborhood rather than a tree. Eight thousand components will not draw
// and would not be readable if they did, so what is asked for is one step at a
// time — and the counts come with it, because descending a graph without them
// is exploring rather than following anything.
//
// Naming a component rather than an identifier: it is what a findings list
// gives out and what somebody composing a request has.
// The choice says which component, where the build ships the name as more
// than one: a name alone is refused as ambiguous, naming the choices, the way
// a finding is.
func (s *Store) Around(ctx context.Context, subject access.Subject, buildID int64,
	name string, which Choice) ([]Neighbor, []Neighbor, error) {

	// Authorized before the name is resolved. Resolved first, the refusal is
	// informative: an absent name, a name held twice and a name held once
	// answer differently, and a subject who may not read findings here reads
	// the build's inventory back one name at a time.
	productID, readable, err := s.visibleIn(ctx, subject, buildID)
	if err != nil {
		return nil, nil, err
	}
	componentID, err := s.ComponentAs(ctx, buildID, name, which)
	if err != nil {
		return nil, nil, err
	}
	below, err := s.step(ctx, readable, buildID, componentID, true)
	if err != nil {
		return nil, nil, err
	}
	above, err := s.step(ctx, readable, buildID, componentID, false)
	if err != nil {
		return nil, nil, err
	}
	// Everything beneath each neighbor, both directions in one statement.
	if err := s.filled(ctx, productID, buildID, readable, above, below); err != nil {
		return nil, nil, err
	}
	// Ordered after that, not before: what a branch is ranked on is what is
	// beneath it, which nothing knows until here.
	ordered(above)
	ordered(below)
	return above, below, nil
}

// filled writes what is open beneath each of these rows, in one statement
// for all of them however many lists they arrive in.
//
// The contents of each of them, not only what is on it. A container holds no
// findings of its own, so without this every one of them reads zero while
// the packages inside hold thousands — and a tree whose counts cannot tell a
// full branch from an empty one is not something anybody can descend by.
func (s *Store) filled(ctx context.Context, productID, buildID int64,
	readable []access.Visibility, lists ...[]Neighbor) error {

	var ids []int64
	for _, rows := range lists {
		for _, row := range rows {
			ids = append(ids, row.ComponentID)
		}
	}
	reached, err := s.reach(ctx, buildID, ids)
	if err != nil {
		return err
	}
	// A finding on a version a rescan replaced is beneath every start reaching
	// the present version of its name, as the list beneath it holds it. The
	// code findings reach replaced versions through their own counter.
	replaced, err := Replaced(ctx, s.db, buildID)
	if err != nil {
		return err
	}
	totals, err := s.beneath(ctx, productID, buildID, readable, withReplaced(reached, replaced))
	if err != nil {
		return err
	}
	codes, err := s.codeBeneath(ctx, buildID, reached)
	if err != nil {
		return err
	}
	for _, rows := range lists {
		for i := range rows {
			bands := totals[rows[i].ComponentID]
			rows[i].BeneathBy = bands
			// Summed from the parts rather than counted twice: an issue has
			// one rating, so the bands partition the distinct issues and the
			// two numbers cannot disagree.
			rows[i].Beneath = 0
			for _, n := range bands {
				rows[i].Beneath += n
			}
			if codes != nil {
				rows[i].CodeFindings = codes.on[rows[i].ComponentID]
				rows[i].CodeBeneath = codes.beneath[rows[i].ComponentID]
			}
		}
	}
	return nil
}

// Roots reports the build's own component and what it pulls in directly.
//
// The root comes back with its children because a tree drawn without it is
// drawn without the thing being explored: every path shown starts one step in,
// and the indentation has nothing to hang from. It is nil where nothing has
// been applied to the build.
//
// What the root pulls in directly includes every component nothing else in
// the build pulls in. The build contains them, and with nothing above them the
// build is what holds them.
func (s *Store) Roots(ctx context.Context, subject access.Subject, buildID int64) (
	*Neighbor, []Neighbor, error) {

	productID, readable, err := s.visibleIn(ctx, subject, buildID)
	if err != nil {
		return nil, nil, err
	}
	var rootID int64
	err = s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."component_id"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, true).
		Limit(1).Scan(ctx, &rootID)
	if database.IsNoRows(err) {
		// Nothing has been applied to this build: every graph applied has a
		// root, because a snapshot without one is refused.
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("look up what this build is: %w", err)
	}
	loose, err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "fn"`).
		Where(`"fn"."build_id" = ?`, buildID).
		Where(`"fn"."closed_scan_id" IS NULL`).
		Where(`"fn"."is_root" = ?`, false).
		Where(orphaned).
		Exists(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("ask whether anything in the build hangs from nothing: %w", err)
	}

	var kids []Neighbor
	if !loose {
		kids, err = s.step(ctx, readable, buildID, rootID, true)
	} else {
		kids, err = s.topLevel(ctx, readable, buildID)
	}
	if err != nil {
		return nil, nil, err
	}
	root, err := s.describe(ctx, readable, buildID, rootID, len(kids))
	if err != nil {
		return nil, nil, err
	}
	// The root and its children counted in the one statement. The root's own
	// number is the whole build's, and it was a second walk of the same edges
	// when asked for on its own. The root's walk reaches what nothing pulls in
	// as well, as every walk beneath the root does.
	top := []Neighbor{*root}
	if err := s.filled(ctx, productID, buildID, readable, top, kids); err != nil {
		return nil, nil, err
	}
	root.Beneath = top[0].Beneath
	root.BeneathBy = top[0].BeneathBy
	root.CodeFindings, root.CodeBeneath = top[0].CodeFindings, top[0].CodeBeneath
	ordered(kids)
	return root, kids, nil
}

// IsRoot is whether a component is a build's root now.
func IsRoot(ctx context.Context, db bun.IDB, buildID, componentID int64) (bool, error) {
	return RootAmong(ctx, db, buildID, []int64{componentID})
}

// Root is a component that was ever a build's root.
type Root struct {
	BuildID     int64 `bun:"build_id"`
	ComponentID int64 `bun:"component_id"`
	// Live is whether it is the build's root now.
	Live bool `bun:"live"`
}

// RootsOf is every component that was ever the root of one of these builds,
// the present ones included, each once per build.
//
// Read from the root index, which holds a build's roots apart from its other
// nodes: a node is never deleted, so the build's whole history is otherwise
// what the read walks.
func RootsOf(ctx context.Context, db bun.IDB, buildIDs []int64) ([]Root, error) {
	if len(buildIDs) == 0 {
		return nil, nil
	}
	var rows []struct {
		BuildID     int64 `bun:"build_id"`
		ComponentID int64 `bun:"component_id"`
		Live        int   `bun:"live"`
	}
	if err := db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."build_id", "n"."component_id"`).
		ColumnExpr(`MAX(CASE WHEN "n"."closed_scan_id" IS NULL THEN 1 ELSE 0 END) AS "live"`).
		Where(`"n"."build_id" IN (?)`, bun.List(buildIDs)).
		Where(`"n"."is_root" = ?`, true).
		GroupExpr(`"n"."build_id", "n"."component_id"`).
		OrderExpr(`"n"."build_id", "n"."component_id"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read every root of %d builds: %w", len(buildIDs), err)
	}
	out := make([]Root, 0, len(rows))
	for _, row := range rows {
		out = append(out, Root{BuildID: row.BuildID, ComponentID: row.ComponentID, Live: row.Live == 1})
	}
	return out, nil
}

// rootsOf is a build's root now, zero where nothing has been applied, and
// every component that was ever its root, the present one included.
func (s *Store) rootsOf(ctx context.Context, buildID int64) (int64, []int64, error) {
	roots, err := RootsOf(ctx, s.db, []int64{buildID})
	if err != nil {
		return 0, nil, err
	}
	var live int64
	ever := make([]int64, 0, len(roots))
	for _, root := range roots {
		ever = append(ever, root.ComponentID)
		if root.Live {
			live = root.ComponentID
		}
	}
	return live, ever, nil
}

// describe reads one component as a neighbor of nothing, for the root.
//
// The child count is passed in rather than counted again: the caller has just
// walked that edge and holds the answer, and asking the database a second time
// for a number already in hand is how the same walk ends up costing twice.
func (s *Store) describe(ctx context.Context, readable []access.Visibility, buildID, componentID int64,
	children int) (*Neighbor, error) {

	row := &Neighbor{Children: children, ComponentID: componentID}
	// Counted exactly as the neighbors are. The root is one row, but a count
	// that is not narrowed the same way is still a count of what the reader
	// may not see.
	err := openIssuesJoin(s.db.NewSelect().
		TableExpr(`"component" AS "c"`), readable, buildID, nil).
		ColumnExpr(`"c"."name" AS "name"`).
		ColumnExpr(`"c"."version" AS "version"`).
		ColumnExpr(`"c"."purl" AS "purl"`).
		Where(`"c"."id" = ?`, componentID).
		Scan(ctx, row)
	// No row is a fault like any other: an open node references its component
	// by foreign key.
	if err != nil {
		return nil, fmt.Errorf("read what this build is: %w", err)
	}
	return row, nil
}

// step walks one edge, downward or upward.
//
// Edges join *nodes* rather than components — a node is a component's presence
// in one build — so both ends go through the node table. Reading the edge
// columns as component identifiers is the mistake this comment exists to stop
// somebody making twice.
func (s *Store) step(ctx context.Context, readable []access.Visibility, buildID, componentID int64,
	down bool) ([]Neighbor, error) {
	near, far := "parent_id", "child_id"
	if !down {
		near, far = far, near
	}

	edges := func() *bun.SelectQuery {
		return s.db.NewSelect().
			TableExpr(`"graph_edge" AS "e"`).
			Join(`JOIN "graph_node" AS "nn" ON "nn"."id" = "e"."`+near+`"`).
			Join(`JOIN "graph_node" AS "fn" ON "fn"."id" = "e"."`+far+`"`).
			Where(`"e"."build_id" = ?`, buildID).
			Where(`"nn"."component_id" = ?`, componentID).
			Where(`"e"."closed_scan_id" IS NULL`).
			// A node is never its own neighbor, as every walk reads it.
			Where(`"e"."parent_id" <> "e"."child_id"`)
	}
	// The neighbors first, so what is counted against each is counted for
	// them alone. Counted for the whole build and joined, the step above the
	// bench kernel groups the build's 325,389 open occurrences for 45 parents
	// carrying none: 32 ms, against 3 ms for the two statements.
	var ids []int64
	if err := edges().ColumnExpr(`DISTINCT "fn"."component_id"`).Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("walk the graph: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var rows []Neighbor
	if err := neighborsAt(edges(), readable, buildID, ids).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("walk the graph: %w", err)
	}

	// Ordered by ordered(), after the caller has filled in what is beneath
	// each — the number a branch is ranked on is not known until then.
	return rows, nil
}

// neighborsAt reads each node the query reaches as "fn" as a neighbor: its
// component, what is open against it and how many things it pulls in, in the
// order a reader descends by. Only is the components the query can reach,
// where they are known, and nil where it may reach any in the build.
func neighborsAt(query *bun.SelectQuery, readable []access.Visibility,
	buildID int64, only []int64) *bun.SelectQuery {

	query = query.Join(`JOIN "component" AS "c" ON "c"."id" = "fn"."component_id"`)
	return childrenJoin(openIssuesJoin(query, readable, buildID, only), buildID, only).
		ColumnExpr(`"c"."id" AS "component_id"`).
		ColumnExpr(NodeName("fn", "c") + ` AS "name"`).
		ColumnExpr(NodeVersion("fn", "c") + ` AS "version"`).
		ColumnExpr(`"c"."purl" AS "purl"`).
		// The node's columns, kids.n and open.n are grouped on as well as
		// selected. Each is one value per c.id, since a build holds one open
		// node per component, and so adds nothing, but the engines that
		// enforce the rule strictly will not take a column from another table
		// on the strength of a primary key belonging to this one.
		GroupExpr(`"c"."id", "c"."name", "c"."version", "fn"."name", "fn"."version", "kids"."n", "open"."n"`).
		// Anything that opens comes before anything that does not, and within
		// each the most findings first.
		//
		// Ordering by findings alone buries the structure: a container holds
		// no findings of its own, so on a real image the root's 5,270
		// children put the first thing that opens at position 546 and every
		// one of the 37 containers below that. A tree whose first screen
		// contains no branches is a list, and the reader never learns the
		// build has containers in it at all.
		// The identifier last, so two components of one name keep one order.
		OrderExpr(`CASE WHEN COALESCE("kids"."n", 0) > 0 THEN 0 ELSE 1 END, "findings" DESC, ` +
			NodeName("fn", "c") + `, "c"."id"`)
}

// openIssuesJoin adds how many issues are open against each component "c" in
// this build, as "findings", narrowed to the visibilities the reader may see.
// Issues rather than finding rows: a library reachable under three parents is
// one issue, not three.
//
// Narrowed like every other count. Without it a reader browsing the tree gets
// an accurate count of the undisclosed findings under each component and can
// bisect down to which one holds them — a leak that needs no row to be shown.
//
// Counted in one grouped pass over the build's open findings and joined,
// rather than asked per row. The covering index over build, closure,
// visibility, issue and component answers the pass without reading a row. As
// a correlated subquery this has two indexes to choose from — the build and
// the component, or the build, open and visibility — and SQLite without
// statistics takes the second, which matches every open row in the build once
// per row: 0.30 s for the root's thirty children against 0.09 s as one grouped
// pass, and 17.1 s for a search for "li" on a switch image of 297,881 open
// findings, where the pass takes 0.24 s.
//
// The pass groups the occurrences to one row per issue on a component before
// counting them. A distinct count over the occurrences sorts all of them: over the
// bench kernel's build, 325,389 open occurrences, the pass takes 103 ms counted
// distinct and 42 ms grouped first.
//
// Where the components the query reaches are known, the pass is over theirs
// alone.
func openIssuesJoin(query *bun.SelectQuery, readable []access.Visibility,
	buildID int64, only []int64) *bun.SelectQuery {

	kinds, kindArgs := kind.Inventory.Where(`"f"."kind"`)
	within, args := "", append([]any{buildID, bun.List(readable)}, kindArgs...)
	if only != nil {
		within, args = ` AND "f"."component_id" IN (?)`, append(args, bun.List(only))
	}
	return query.
		Join(`LEFT JOIN (SELECT "g"."cid" AS "cid", COUNT(*) AS "n"
			FROM (SELECT "f"."component_id" AS "cid", "f"."vulnerability_id" AS "vid"
			      FROM "finding" AS "f"
			      WHERE "f"."build_id" = ? AND "f"."closed_at" IS NULL AND "f"."visibility" IN (?)
			        AND `+kinds+within+`
			      GROUP BY "f"."component_id", "f"."vulnerability_id") AS "g"
			GROUP BY "g"."cid") AS "open" ON "open"."cid" = "c"."id"`, args...).
		ColumnExpr(`COALESCE("open"."n", 0) AS "findings"`)
}

// childrenJoin adds how many things each component "c" pulls in in this build,
// as "children", so a node that opens can be told from one that does not
// before somebody clicks it.
//
// Counted once for the whole build and joined, rather than asked per row. As a
// correlated subquery this has no index to take: it is bound on the child's
// component, while the only way into the edge table is the build, so each
// row scans every edge in the build. Measured on a switch operating-system
// image — 19,192 edges, 5,270 components directly under the root — that column
// alone cost 5.06 s against 0.106 s for one pass. An index on the node's
// component made it worse (5.4 s to 10.0 s), because the scan being repeated is
// over the edges rather than the lookup it drives.
//
// Where the components the query reaches are known, the pass is over theirs
// alone.
func childrenJoin(query *bun.SelectQuery, buildID int64, only []int64) *bun.SelectQuery {
	within, args := "", []any{buildID}
	if only != nil {
		within, args = ` AND "dp"."component_id" IN (?)`, append(args, bun.List(only))
	}
	return query.
		Join(`LEFT JOIN (SELECT "dp"."component_id" AS "cid", COUNT(*) AS "n"
			FROM "graph_edge" AS "d"
			JOIN "graph_node" AS "dp" ON "dp"."id" = "d"."parent_id"
			WHERE "d"."build_id" = ? AND "d"."closed_scan_id" IS NULL
			  AND "d"."parent_id" <> "d"."child_id"`+within+`
			GROUP BY "dp"."component_id") AS "kids" ON "kids"."cid" = "c"."id"`, args...).
		ColumnExpr(`COALESCE("kids"."n", 0) AS "children"`)
}

// orphaned is the condition that nothing in the build pulls in the node the
// query reaches as "fn".
//
// Asked by the node alone. A node belongs to one build, so naming the build as
// well adds nothing, and it steers SQLite onto the index led by the build,
// where the child is the fourth column: every open edge in the build scanned
// once per node, 7.28 s for 59,982 nodes against 45 ms on the index led by the
// child.
//
// An edge from the node to itself pulls nothing in, as every walk reads it.
const orphaned = `NOT EXISTS (SELECT 1 FROM "graph_edge" AS "pe"
	WHERE "pe"."child_id" = "fn"."id" AND "pe"."closed_scan_id" IS NULL
	  AND "pe"."parent_id" <> "pe"."child_id")`

// topLevel reads what the root pulls in and what nothing pulls in, as one
// list in one statement: the two are read with the same per-build counts, and
// read apart each pays for them.
//
// A document that states no edge from its root still lists what the build
// contains, and a component with no parent is contained by nothing else. One
// real switch image arrived with 60,935 components, 1,358 edges and none of
// them from the root, and drawn from the root alone its tree was empty.
func (s *Store) topLevel(ctx context.Context, readable []access.Visibility,
	buildID int64) ([]Neighbor, error) {

	var rows []Neighbor
	err := neighborsAt(s.db.NewSelect().TableExpr(`"graph_node" AS "fn"`), readable, buildID, nil).
		Where(`"fn"."build_id" = ?`, buildID).
		Where(`"fn"."closed_scan_id" IS NULL`).
		Where(`"fn"."is_root" = ?`, false).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where(orphaned).
				WhereOr(`EXISTS (SELECT 1 FROM "graph_edge" AS "re"
					JOIN "graph_node" AS "rn" ON "rn"."id" = "re"."parent_id"
					WHERE "re"."child_id" = "fn"."id" AND "re"."closed_scan_id" IS NULL
					  AND "rn"."is_root" = ?)`, true)
		}).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what the build holds directly: %w", err)
	}
	return rows, nil
}

// ordered puts a list of neighbors in the order somebody reads it: what opens
// first, and within each group the most findings first.
//
// The number a row is ranked on is the number that describes it: for a
// branch, everything open beneath it, and for a leaf, its own count — which
// for a leaf are the same number anyway. A container holds nothing of its own,
// so ranked on that every container reads zero and the list is alphabetical.
//
// A node that opens comes before one that does not. On a real image the root's
// 5,270 children put the first thing that opens at position 546 unless
// structure is held above contents. A tree whose first screen contains no
// branches is a list, and the reader never learns the build has containers in
// it.
//
// The cost: an edge here means "contains or depends on" and the document does
// not distinguish the two, so forty kernel-module packages each depending on
// the one kernel each report the kernel's findings beneath them, and deep in a
// tree they group together at the top. Ranked by name they would not, and
// every other list would be an alphabetical list of containers.
func ordered(rows []Neighbor) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if (a.Children > 0) != (b.Children > 0) {
			return a.Children > 0
		}
		if ranks(a) != ranks(b) {
			return ranks(a) > ranks(b)
		}
		return a.Name < b.Name
	})
}

// ranks is what a row is ordered on: everything open beneath it, which for a
// leaf is its own count.
func ranks(n Neighbor) int {
	if n.Beneath > n.Findings {
		return n.Beneath
	}
	return n.Findings
}

// knowsBuild refuses somebody who may not know this build exists.
//
// The weaker of the two questions here, and the right one for a read that
// carries no findings: the way down to a component is the build's shape rather
// than what is open against it. It admits a case collaborator, which is the
// same rule the catalog's own lookup applies — the names their issue sits at
// have to resolve, and so does the path to the component it sits in, or the
// grant shows them a row they cannot open.
//
// visibleIn is the other question and stays where counts are answered. A count
// of findings narrowed by a case grant would be a count of the product's work,
// and that is what a collaborator may not have.
func (s *Store) knowsBuild(ctx context.Context, subject access.Subject, buildID int64) error {
	productID, err := catalog.NewStore(s.db).ProductOf(ctx, buildID)
	if err != nil {
		return err
	}
	if !subject.Reaches(productID) {
		return access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	return nil
}

// visibleIn reports the visibilities this subject may read in a build, and
// refuses where they may read none.
//
// The graph is browsed beside a findings list that is narrowed correctly, so a
// count here that is not narrowed the same way is the more dangerous of the
// two: nobody looking at it expects it to be a disclosure.
func (s *Store) visibleIn(ctx context.Context, subject access.Subject, buildID int64) (int64, []access.Visibility, error) {
	productID, err := catalog.NewStore(s.db).ProductOf(ctx, buildID)
	if err != nil {
		return 0, nil, err
	}
	readable, err := access.Readable(subject, productID)
	if err != nil {
		return 0, nil, err
	}
	// The product comes back with what may be read in it, because the rating
	// a band is drawn from belongs to that same product: a count severity-
	// banded for one product while authorized against another is the fault
	// this pair exists to make unspellable.
	return productID, readable, nil
}

// Step is one component on the way down to another.
type Step struct {
	Name    string
	Version string
	// Purl is the step's package identifier, which its ecosystem and
	// namespace are read out of: the tree names a row by all four.
	Purl string
}

// Counts reports how much the build's graph holds, which is what the screen
// showing it says at the top.
//
// Two numbers rather than one because they answer different questions: how
// much was inventoried, and how much of it was placed. A build with many
// components and few edges is a document that listed everything and said
// where almost nothing went.
func (s *Store) Counts(ctx context.Context, subject access.Subject, buildID int64) (Tally, error) {
	if _, _, err := s.visibleIn(ctx, subject, buildID); err != nil {
		return Tally{}, err
	}
	components, err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		// The build's own root is not one of its components, which is what the
		// list beside this number says.
		Where(`"n"."is_root" = ?`, false).
		Count(ctx)
	if err != nil {
		return Tally{}, fmt.Errorf("count what this build holds: %w", err)
	}
	edges, err := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Where(`"e"."build_id" = ?`, buildID).
		Where(`"e"."closed_scan_id" IS NULL`).
		// An edge from a component to itself places nothing.
		Where(`"e"."parent_id" <> "e"."child_id"`).
		Count(ctx)
	if err != nil {
		return Tally{}, fmt.Errorf("count what this build's edges are: %w", err)
	}
	// What the scanner has no way to match. It ships and is tracked, and no
	// scan can say anything about it, so a build of nothing else reports no
	// findings and reads as clean.
	unmatched, err := s.unmatchedCount(ctx, buildID)
	if err != nil {
		return Tally{}, err
	}
	return Tally{Components: int(components), Edges: int(edges), Unmatched: unmatched}, nil
}

// Tally is how much a build's graph holds.
type Tally struct {
	Components int
	Edges      int
	// Unmatched is how many of the components the scanner has no way to match,
	// for any of the reasons Unmatchable gives.
	Unmatched int
}

// Search finds components of a build by name.
//
// Opening nodes does not find anything in a graph this size — eight thousand
// components under a root with five thousand children — so searching is the
// way in and browsing is for answering "what else is under this" once somebody
// is already somewhere. A tree without it is a tree nobody reaches the middle
// of.
//
// Matched on a substring of the name, case-folded, because somebody looking
// for openssl types "ssl" and should not have to know whether the package is
// called openssl, libssl3t64 or symcrypt-openssl. Ordered by findings so the
// first answer is the one worth opening.
func (s *Store) Search(ctx context.Context, subject access.Subject, buildID int64,
	term string, limit int) ([]Neighbor, error) {

	productID, readable, err := s.visibleIn(ctx, subject, buildID)
	if err != nil {
		return nil, err
	}
	term = strings.TrimSpace(term)
	if term == "" {
		return nil, nil
	}
	limit = database.AList.Of(limit)

	// The components matched, each once however many occurrences it sits at. The
	// name is matched on its folded form, the component's or the one the build
	// stated, which is lowercased and trimmed
	// when stored, so no engine is asked to compare loosely; and the term is
	// escaped as well as folded, so a term of "%" searches for a percent sign.
	// The build's own root is not one of its components, which is what the
	// count beside the list says.
	matched := `(SELECT DISTINCT "n"."component_id" AS "cid",
		` + NodeName("n", "m") + ` AS "stated_name", ` + NodeVersion("n", "m") + ` AS "stated_version"
		FROM "graph_node" AS "n"
		JOIN "component" AS "m" ON "m"."id" = "n"."component_id"
		WHERE "n"."build_id" = ? AND "n"."closed_scan_id" IS NULL AND "n"."is_root" = ?
		  AND ("m"."name_folded" LIKE ?` + database.LikeClause + `
		    OR "n"."name_folded" LIKE ?` + database.LikeClause + `)) AS "matched"`

	var rows []Neighbor
	like := "%" + database.LikeEscaped(Folded(term)) + "%"
	query := s.db.NewSelect().
		TableExpr(matched, buildID, false, like, like).
		Join(`JOIN "component" AS "c" ON "c"."id" = "matched"."cid"`)
	err = childrenJoin(openIssuesJoin(query, readable, buildID, nil), buildID, nil).
		ColumnExpr(`"c"."id" AS "component_id"`).
		ColumnExpr(`"matched"."stated_name" AS "name"`).
		ColumnExpr(`"matched"."stated_version" AS "version"`).
		ColumnExpr(`"c"."purl" AS "purl"`).
		// The identifier last, because a build ships one name at more than
		// one version and the limit cuts by this order.
		OrderExpr(`"findings" DESC, "matched"."stated_name", "c"."id"`).
		Limit(int64(limit)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("search the build: %w", err)
	}
	// What is beneath each hit, by the statement the tree uses, so a hit and
	// the same component browsed to carry one number. The page stays ranked
	// on each hit's own findings, which is what the limit above cuts by.
	if err := s.filled(ctx, productID, buildID, readable, rows); err != nil {
		return nil, err
	}
	return rows, nil
}
