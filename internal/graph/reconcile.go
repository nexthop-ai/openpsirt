package graph

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// reconcileNodes brings the open nodes for a variant in line with what a scan
// describes, and reports how many it opened and closed.
//
// Nodes that are still present are left completely alone: not touched, not
// re-stamped, not rewritten. That is what makes an unchanged rebuild free.
func reconcileNodes(ctx context.Context, tx bun.Tx, targetID, scanID int64, wanted map[int64]bool) (map[int64]int64, int, int, error) {
	var open []Node
	err := tx.NewSelect().Model(&open).
		Where("target_id = ?", targetID).
		Where("closed_scan_id IS NULL").
		Scan(ctx)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read open nodes: %w", err)
	}

	nodeIDs := make(map[int64]int64, len(wanted))
	// Whether each kept node is the build's root, which the scan just said and
	// the row may disagree with. Only ever written on an insert, a component
	// promoted to the top of a graph it was already in kept its old answer —
	// and the build then reported no root of its own.
	reroot := map[int64]bool{}
	var gone []int64
	for _, node := range open {
		if isRoot, keep := wanted[node.ComponentID]; keep {
			nodeIDs[node.ComponentID] = node.ID
			if node.IsRoot != isRoot {
				reroot[node.ID] = isRoot
			}
			continue
		}
		gone = append(gone, node.ID)
	}

	var missing []Node
	for componentID, isRoot := range wanted {
		if _, have := nodeIDs[componentID]; have {
			continue
		}
		missing = append(missing, Node{
			TargetID: targetID, ComponentID: componentID,
			IsRoot: isRoot, OpenedScanID: scanID,
		})
	}
	if len(missing) > 0 {
		if err := database.InBatches(ctx, tx, missing); err != nil {
			return nil, 0, 0, fmt.Errorf("open %d nodes: %w", len(missing), err)
		}
		for _, node := range missing {
			nodeIDs[node.ComponentID] = node.ID
		}
	}

	// What the scan says is the root, where the row disagrees. Two statements
	// at most, because a build has one root and at most one node loses it.
	for _, isRoot := range []bool{true, false} {
		var ids []int64
		for id, becomes := range reroot {
			if becomes == isRoot {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			continue
		}
		err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewUpdate().Model((*Node)(nil)).
				Set("is_root = ?", isRoot).
				Where("id IN (?)", bun.List(batch)).Exec(ctx)
			return err
		})
		if err != nil {
			return nil, 0, 0, fmt.Errorf("record which node is the root: %w", err)
		}
	}

	if len(gone) > 0 {
		// Closed, never deleted. What a release contained is a question asked
		// years later, and a deleted row cannot answer it.
		err := database.IDsInBatches(ctx, gone, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewUpdate().Model((*Node)(nil)).
				Set("closed_scan_id = ?", scanID).
				Where("id IN (?)", bun.List(batch)).Exec(ctx)
			return err
		})
		if err != nil {
			return nil, 0, 0, fmt.Errorf("close %d nodes: %w", len(gone), err)
		}
	}
	return nodeIDs, len(missing), len(gone), nil
}

// reconcileEdges does the same for dependencies.
func reconcileEdges(ctx context.Context, tx bun.Tx, targetID, scanID int64, wanted map[[2]int64]bool) (int, int, error) {
	var open []Edge
	err := tx.NewSelect().Model(&open).
		Where("target_id = ?", targetID).
		Where("closed_scan_id IS NULL").
		Scan(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("read open edges: %w", err)
	}

	have := make(map[[2]int64]bool, len(open))
	var gone []int64
	for _, edge := range open {
		key := [2]int64{edge.ParentID, edge.ChildID}
		if wanted[key] {
			have[key] = true
			continue
		}
		gone = append(gone, edge.ID)
	}

	var missing []Edge
	for key := range wanted {
		if have[key] {
			continue
		}
		missing = append(missing, Edge{
			TargetID: targetID, ParentID: key[0], ChildID: key[1], OpenedScanID: scanID,
		})
	}
	if len(missing) > 0 {
		if err := database.InBatches(ctx, tx, missing); err != nil {
			return 0, 0, fmt.Errorf("open %d edges: %w", len(missing), err)
		}
	}
	if len(gone) > 0 {
		err := database.IDsInBatches(ctx, gone, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewUpdate().Model((*Edge)(nil)).
				Set("closed_scan_id = ?", scanID).
				Where("id IN (?)", bun.List(batch)).Exec(ctx)
			return err
		})
		if err != nil {
			return 0, 0, fmt.Errorf("close %d edges: %w", len(gone), err)
		}
	}
	return len(missing), len(gone), nil
}
