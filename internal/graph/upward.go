package graph

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

// The tree, seen upward, for somebody narrowed to their own work.
//
// **The tree downward is the inventory.** Rooted at the build and descended, it
// is what the product contains — which is the breadth a person holding no
// reading on the product was deliberately not granted. So it cannot be offered
// with rows hidden: a container's count would still say how much sits under it,
// and opening one asks a question they may not ask.
//
// **What they get instead is the chains their own findings sit on**, from each
// finding's component up to the build's root. The chain upward is what makes a
// finding judgeable, because it says what pulled the thing in — and every node
// on it sits above something they were already given, so nothing on it is new.
// Descending a node is the question that stays closed.
//
// **The counts are narrowed to match.** A node says how much of *their* work
// hangs beneath it along these chains, never how much the build holds there. A
// number that counted the build would be the inventory leaking through a tree
// drawn to avoid it.

// Upward is one node of the tree the subject's own work hangs from.
type Upward struct {
	Component string
	Version   string
	// Depth is how far below the root it sits, so a caller draws the tree by
	// indenting rather than by holding a structure.
	Depth int
	// Findings is their own open issues on this component itself, and Beneath
	// the same at or under it along these chains. Both are counts of theirs:
	// what the build holds here is not answered.
	Findings int
	Beneath  int
	// Placed is false for a component the inventory put nowhere, or whose
	// every way up runs past the bound. Those sit at the top with no chain,
	// which is the honest answer rather than hanging them off the root.
	Placed bool
}

// ours is the most components of somebody's own this will assemble a tree
// over. Past it the tree is incomplete and says so, rather than being drawn
// with counts that are quietly wrong.
const ours = 2000

// Ours is the tree of what this subject holds in one build, seen upward.
//
// **No reading on the product is asked for.** An assignment is itself a grant
// of visibility of what was assigned, which is what gives a
// capability held without a read role any content at all — so the population
// here is what they hold, at the visibility they may read it at and no
// further. Somebody who holds nothing gets nothing, which is not a refusal:
// there is no work of theirs here to hang a tree from.
//
// Complete is false where they hold work on more components than this will
// assemble. The tree is then a part of the answer and the counts under-report,
// so it is said rather than left to be noticed.
func (s *Store) Ours(ctx context.Context, subject access.Subject, targetID int64) (
	[]Upward, bool, error) {

	mine := subject.Mine()
	if subject.Kind != access.Person || len(mine) == 0 {
		return nil, true, nil
	}
	productID, err := catalog.NewStore(s.db).ProductOf(ctx, targetID)
	if err != nil {
		return nil, false, err
	}

	var rows []struct {
		ComponentID int64  `bun:"component_id"`
		Name        string `bun:"name"`
		Version     string `bun:"version"`
		Issues      int    `bun:"issues"`
	}
	held := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`MIN(c.name) AS "name"`).
		ColumnExpr(`MIN(c.version) AS "version"`).
		ColumnExpr(`COUNT(DISTINCT f.vulnerability_id) AS "issues"`).
		Where("f.target_id = ?", targetID).
		Where("f.closed_at IS NULL").
		Where("f.assigned_to IN (?)", bun.List(mine)).
		GroupExpr("f.component_id").
		OrderExpr("issues DESC, name").
		Limit(ours + 1)
	// An assignment carries the row at the visibility they may read it at, so
	// somebody who may not read undisclosed work does not get it here either
	// — the same clause the work list applies, for the same reason.
	if !subject.Reads(access.Private, productID) {
		held = held.Where("f.visibility = ?", access.Public)
	}
	if err := held.Scan(ctx, &rows); err != nil {
		return nil, false, fmt.Errorf("read what you hold in this build: %w", err)
	}
	if len(rows) == 0 {
		return nil, true, nil
	}
	complete := len(rows) <= ours
	if !complete {
		rows = rows[:ours]
	}

	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ComponentID)
	}
	climbed, err := s.climb(ctx, targetID, ids)
	if err != nil {
		return nil, false, err
	}
	chains := unwind(climbed)

	// Merged by path rather than by component, because a tree is paths: the
	// same library under two containers is two places somebody is looking at,
	// and the shortest way down is the one each chain already carries.
	root := &node{}
	unplaced := make([]Upward, 0)
	for _, row := range rows {
		chain := chains[row.ComponentID]
		if len(chain) == 0 {
			unplaced = append(unplaced, Upward{
				Component: row.Name, Version: row.Version,
				Findings: row.Issues, Beneath: row.Issues,
			})
			continue
		}
		at := root
		for _, step := range chain {
			at = at.child(step)
		}
		at.findings += row.Issues
	}
	sort.SliceStable(unplaced, func(i, j int) bool {
		if unplaced[i].Beneath != unplaced[j].Beneath {
			return unplaced[i].Beneath > unplaced[j].Beneath
		}
		return unplaced[i].Component < unplaced[j].Component
	})

	out := make([]Upward, 0, len(rows))
	for _, top := range root.kids {
		top.total()
	}
	root.emit(&out, -1)
	return append(out, unplaced...), complete, nil
}

// node is one component on the way to work of the subject's own, while the
// tree is being assembled.
type node struct {
	step     Step
	kids     []*node
	at       map[string]*node
	findings int
	beneath  int
}

func (n *node) child(step Step) *node {
	key := step.Name + "@" + step.Version
	if n.at == nil {
		n.at = map[string]*node{}
	}
	if held, seen := n.at[key]; seen {
		return held
	}
	made := &node{step: step}
	n.at[key] = made
	n.kids = append(n.kids, made)
	return made
}

// total sums what hangs beneath each node and orders the children by it, which
// is the order the tree downward uses: the branch worth opening first.
func (n *node) total() int {
	n.beneath = n.findings
	for _, kid := range n.kids {
		n.beneath += kid.total()
	}
	sort.SliceStable(n.kids, func(i, j int) bool {
		if n.kids[i].beneath != n.kids[j].beneath {
			return n.kids[i].beneath > n.kids[j].beneath
		}
		return n.kids[i].step.Name < n.kids[j].step.Name
	})
	return n.beneath
}

// emit writes the tree in the order it is drawn, parents before children.
func (n *node) emit(out *[]Upward, depth int) {
	if depth >= 0 {
		*out = append(*out, Upward{
			Component: n.step.Name, Version: n.step.Version,
			Depth: depth, Findings: n.findings, Beneath: n.beneath, Placed: true,
		})
	}
	for _, kid := range n.kids {
		kid.emit(out, depth+1)
	}
}
