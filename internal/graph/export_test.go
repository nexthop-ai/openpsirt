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
