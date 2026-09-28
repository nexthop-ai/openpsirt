// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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
// A node that is still present is written only where what the scan says about
// it differs from the row: its root flag, or the identifiers the build stated
// for it. An unchanged rebuild writes nothing.
func reconcileNodes(ctx context.Context, tx bun.IDB, targetID, scanID int64,
	wanted map[int64]stated) (map[int64]int64, int, int, error) {

	var open []Node
	err := tx.NewSelect().Model(&open).
		Where("target_id = ?", targetID).
		Where("closed_scan_id IS NULL").
		Scan(ctx)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("read open nodes: %w", err)
	}

	nodeIDs := make(map[int64]int64, len(wanted))
	// Each kept node's root flag, which the scan just said and the row may
	// disagree with. Left alone, a component promoted to the top of a graph
	// it was already in keeps its old answer, and the build reports no root
	// of its own.
	reroot := map[int64]bool{}
	// Each kept node whose stated identifiers moved: a distribution release
	// named in a qualifier moves without the package's version moving.
	restated := map[int64]stated{}
	var gone []int64
	for _, node := range open {
		if says, keep := wanted[node.ComponentID]; keep {
			nodeIDs[node.ComponentID] = node.ID
			if node.IsRoot != says.isRoot {
				reroot[node.ID] = says.isRoot
			}
			if node.Purl != says.purl || node.CPE != says.cpe {
				restated[node.ID] = says
			}
			continue
		}
		gone = append(gone, node.ID)
	}

	var missing []Node
	for componentID, says := range wanted {
		if _, have := nodeIDs[componentID]; have {
			continue
		}
		missing = append(missing, Node{
			TargetID: targetID, ComponentID: componentID,
			IsRoot: says.isRoot, OpenedScanID: scanID,
			Purl: says.purl, CPE: says.cpe,
		})
	}
	// One statement per node. A build restates an identifier rarely, and
	// when a distribution release moves under an unchanged version every
	// package it names moves with it, each to a string of its own.
	for id, says := range restated {
		if _, err := tx.NewUpdate().Model((*Node)(nil)).
			Set("purl = ?", nullable(says.purl)).
			Set("cpe = ?", nullable(says.cpe)).
			Where("id = ?", id).Exec(ctx); err != nil {
			return nil, 0, 0, fmt.Errorf("record what the build states about a component: %w", err)
		}
	}
	if len(missing) > 0 {
		if err := database.InBatches(ctx, tx, missing); err != nil {
			return nil, 0, 0, fmt.Errorf("open %d nodes: %w", len(missing), err)
		}
		for _, node := range missing {
			nodeIDs[node.ComponentID] = node.ID
		}
	}

	// The scan's own root, where the row disagrees. Two statements
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

// stated is what a scan says about one component's place in a build: whether
// it is the build's root, and the identifiers the build stated for it.
type stated struct {
	isRoot    bool
	purl, cpe string
}

// nullable is a stated identifier as the column holds it: absent where the
// build stated none, which is how an insert writes it too.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// edgeAt identifies one declared dependency: the pair and what the producer
// said the dependency's scope is.
//
// The scope is part of the key. A producer that starts describing the same
// pair differently has said something different, and an edge carrying the
// earlier word while the document says another is a record of what nobody
// sent. Closing the one and opening the other is what every other change to a
// graph does here, and it keeps the counts a scan reports true.
type edgeAt struct {
	Parent, Child int64
	Kind          string
}

// reconcileEdges does the same for dependencies.
func reconcileEdges(ctx context.Context, tx bun.IDB, targetID, scanID int64, wanted map[edgeAt]bool) (int, int, error) {
	var open []Edge
	err := tx.NewSelect().Model(&open).
		Where("target_id = ?", targetID).
		Where("closed_scan_id IS NULL").
		Scan(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("read open edges: %w", err)
	}

	have := make(map[edgeAt]bool, len(open))
	var gone []int64
	for _, edge := range open {
		key := edgeAt{Parent: edge.ParentID, Child: edge.ChildID, Kind: edge.Kind}
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
			TargetID: targetID, ParentID: key.Parent, ChildID: key.Child, Kind: key.Kind,
			OpenedScanID: scanID,
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
