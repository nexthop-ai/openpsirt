// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import "context"

// CurrentNodes returns the components present in a build now, for a test that
// asserts what an applied graph left standing.
func (s *Store) CurrentNodes(ctx context.Context, targetID int64) ([]Node, error) {
	var nodes []Node
	err := s.db.NewSelect().Model(&nodes).
		Where("target_id = ?", targetID).
		Where("closed_scan_id IS NULL").
		Scan(ctx)
	return nodes, err
}

// Climbed returns how many nodes and how many edges between them the climb
// from these components read, for a test that pins what a looping document
// costs.
func (s *Store) Climbed(ctx context.Context, targetID int64, componentIDs []int64) (nodes, edges int, err error) {
	r, err := s.climb(ctx, targetID, componentIDs)
	if err != nil {
		return 0, 0, err
	}
	for _, held := range r.parents {
		edges += len(held)
	}
	return len(r.at), edges, nil
}

// Ours is the most components the upward tree assembles over.
const Ours = ours
