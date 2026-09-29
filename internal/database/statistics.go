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
// The form that checks every table rather than those this connection has
// queried, because a pooled connection may have queried none. It analyzes a
// table only where the statistics are missing or the table has grown well
// past them: 5 ms where nothing moved, 0.7 s for the demo with none at all.
func RefreshStatistics(ctx context.Context, db *DB) error {
	if db.Server.Engine != SQLite {
		return nil
	}
	if _, err := db.ExecContext(ctx, "PRAGMA optimize=0x10002"); err != nil {
		return fmt.Errorf("refresh the planner's statistics: %w", err)
	}
	return nil
}
