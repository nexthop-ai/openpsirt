// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"context"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// ApplyGraph records a scan's graph against a build in a transaction of its
// own, as ingest does inside the one it opens for the whole scan.
func ApplyGraph(ctx context.Context, db bun.IDB, targetID, scanID int64,
	snap graph.Snapshot) (graph.Applied, error) {

	var applied graph.Applied
	err := database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		applied, err = graph.ApplyWithin(ctx, tx, targetID, scanID, snap)
		return err
	})
	return applied, err
}

// RecordClaims stores what a build argued in a transaction of its own, as
// ingest does inside the one it opens for the whole scan.
func RecordClaims(ctx context.Context, db bun.IDB, targetID, scanID int64,
	claims []sbom.Suppression, stated map[sbom.Origin]bool) (finding.ClaimsApplied, error) {

	var applied finding.ClaimsApplied
	err := database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		applied, err = finding.RecordClaimsWithin(ctx, tx, targetID, scanID, claims, stated)
		return err
	})
	return applied, err
}
