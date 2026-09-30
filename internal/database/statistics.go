// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"
	"fmt"
)

// RefreshStatistics brings the planner's statistics up to date where the
// engine does not keep them itself.
//
// SQLite gathers none unless asked, and without them it chooses an index by
// how many columns an equality matches rather than by how many rows lie
// behind it. On a demo holding 361,429 findings, a review-queue statement
// took 4.0 s walking 297,405 of one component's findings when an index on
// the place reached the few it wanted in 0.6 ms, and the list of what is
// running out took 2.5 s where it takes 0.13 s. The servers keep statistics
// current on their own, so on them this does nothing.
//
// A whole ANALYZE rather than the pragma that analyzes only a table that has
// grown several times over. A scan changes the shape of the tables more than
// their size: the demo's second build added a tenth to the findings, so the
// statistics went on describing every finding as under one build, and the
// findings list took 2.1 s where it takes 0.57 s. 0.66 s for the demo's
// 361,429 findings. Sampling the first rows of each index instead took 71 ms
// and misjudged which rows were assigned, which cost the assignments count
// 0.68 s.
func RefreshStatistics(ctx context.Context, db *DB) error {
	if db.Server.Engine != SQLite {
		return nil
	}
	if _, err := db.ExecContext(ctx, "ANALYZE"); err != nil {
		return fmt.Errorf("refresh the planner's statistics: %w", err)
	}
	return nil
}
