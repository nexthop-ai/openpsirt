// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ErrNoInventory says a build has never had an inventory read for it.
//
// Compared against one, every name the other build holds would read as added
// or removed, which is a claim about two builds made from one of them.
var ErrNoInventory = refusal.New("no inventory has been read for that build")

// Between is every name two builds' inventories differ on, as each stands now.
//
// The builds are any two a subject reaches: two releases, two platforms of one
// release, or a tag and the branch it was cut from. Before is what the first
// holds and After what the second holds, so a name only the second holds is
// added and one only the first holds is removed.
//
// The listing of one upload is the same fold over different sides, so a name
// is compared the same way whichever question asked it: by its folded name,
// with every version on each side, removals first.
func (s *Store) Between(ctx context.Context, subject access.Subject, fromID, toID int64,
	only ChangeKind, limit, offset int) ([]Change, int, error) {

	names := catalog.NewStore(s.db)
	for _, targetID := range []int64{fromID, toID} {
		productID, err := names.ProductOf(ctx, targetID)
		if err != nil {
			return nil, 0, err
		}
		// What two builds shipped, rather than what is open against either,
		// so the question is whether this subject reaches each build at all.
		if !subject.Sees(productID) {
			return nil, 0, access.Denied(fmt.Sprintf("read what product %d contains", productID))
		}
	}

	// Every row each build holds now. The root comes back too, as the proof
	// that the build has an inventory at all: it opens with the first graph
	// applied and some root stands for as long as the build has one.
	var nodes []struct {
		Target  int64  `bun:"tgt"`
		Root    bool   `bun:"rt"`
		Name    string `bun:"nm"`
		Display string `bun:"dsp"`
		Version string `bun:"ver"`
	}
	err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
		ColumnExpr(`n.target_id AS "tgt"`).
		ColumnExpr(`n.is_root AS "rt"`).
		ColumnExpr(`c.name_folded AS "nm"`).
		ColumnExpr(`c.name AS "dsp"`).
		ColumnExpr(`c.version AS "ver"`).
		Where("n.target_id IN (?)", bun.List([]int64{fromID, toID})).
		Where("n.closed_scan_id IS NULL").
		Scan(ctx, &nodes)
	if err != nil {
		return nil, 0, fmt.Errorf("read what two builds contain: %w", err)
	}

	// One row per version of a name, standing on the first side, the second,
	// or both. The fold reads the rows of one comparison under one key, and
	// this comparison is the only one here.
	type key struct{ name, version string }
	folded := map[key]*movedRow{}
	var order []key
	held := map[int64]bool{}
	for _, node := range nodes {
		held[node.Target] = true
		if node.Root {
			// Not one of the build's components, its version is not stored,
			// and its name differs per variant.
			continue
		}
		k := key{node.Name, node.Version}
		row, ok := folded[k]
		if !ok {
			row = &movedRow{Name: node.Name, Display: node.Display, Version: node.Version}
			folded[k] = row
			order = append(order, k)
		} else if node.Display < row.Display {
			row.Display = node.Display
		}
		// One build compared with itself stands on both sides of every row,
		// which is no change anywhere.
		if node.Target == fromID {
			row.Had = 1
		}
		if node.Target == toID {
			row.Has = 1
		}
	}
	if !held[fromID] || !held[toID] {
		return nil, 0, ErrNoInventory
	}

	rows := make([]movedRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, *folded[k])
	}
	return paged(changed(rows)[0], only, limit, offset)
}
