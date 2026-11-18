// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// UploadPoint is one upload of a build, at the build time its inventory
// states, with what the build held open while it was current.
type UploadPoint struct {
	ScanID  int64
	BuiltAt time.Time
	// AsOf is the moment counted: the start of the last scan of the build
	// while this inventory was current, or now for the inventory the build
	// holds.
	AsOf    time.Time
	Current bool
	finding.Held
}

// BuildTrend is one build's exposure upload by upload, oldest first, for the
// latest limit uploads applied to its graph, as many as a chart plots.
//
// An inventory is current from its arrival until the next applied one
// arrives, as the replaced-inventory check reads it. A replaced inventory is
// counted at the start of the last successful scan of the build, other than a
// check, that started while it was current: what was known of it then,
// never rescanned against today's data. The inventory the build holds is
// counted now. An inventory no scan reached is no point.
func (s *Store) BuildTrend(ctx context.Context, subject access.Subject, scope finding.Scope,
	within finding.Within, limit int) ([]UploadPoint, error) {

	limit = database.APlot.Of(limit)
	findings := finding.NewStore(s.db)
	buildID, err := findings.OneBuild(ctx, subject, scope)
	if err != nil {
		return nil, err
	}

	// Newest first, by the order uploads apply in, so the first is the one
	// the build holds.
	var uploads []struct {
		ID         int64     `bun:"id"`
		BuiltAt    time.Time `bun:"built_at"`
		ReceivedAt time.Time `bun:"received_at"`
	}
	if err := Applied(s.db.NewSelect().
		TableExpr(`"scan" AS "sc"`).
		ColumnExpr(`"sc"."id" AS "id"`).
		ColumnExpr(`"sc"."built_at" AS "built_at"`).
		ColumnExpr(`"sc"."received_at" AS "received_at"`).
		Where(`"sc"."build_id" = ?`, buildID), "sc").
		OrderExpr(`"sc"."id" DESC`).Limit(int64(limit)).
		Scan(ctx, &uploads); err != nil {
		return nil, fmt.Errorf("read the uploads of the build: %w", err)
	}
	if len(uploads) == 0 {
		return nil, nil
	}

	// The scans of the build since the oldest of them arrived, oldest first.
	var runs []finding.Run
	if err := s.db.NewSelect().Model(&runs).
		Column("id", "started_at").
		Where(`"build_id" = ?`, buildID).
		Where(`"checked_scan_id" IS NULL`).
		Where(`"finished_at" IS NOT NULL`).
		Where(`COALESCE("failure", '') = ''`).
		Where(`"started_at" >= ?`, uploads[len(uploads)-1].ReceivedAt).
		Order("started_at ASC", "id ASC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the scans of the build: %w", err)
	}

	now := s.now().UTC()
	var points []UploadPoint
	var moments []time.Time
	for i, up := range uploads {
		var replaced *time.Time
		if i > 0 {
			replaced = &uploads[i-1].ReceivedAt
		}
		// The last scan that started while this inventory was current.
		var last *time.Time
		for _, run := range runs {
			if run.StartedAt.Before(up.ReceivedAt) {
				continue
			}
			if replaced != nil && !run.StartedAt.Before(*replaced) {
				break
			}
			last = &run.StartedAt
		}
		if last == nil {
			continue
		}
		at := *last
		if replaced == nil {
			at = now
		}
		points = append(points, UploadPoint{ScanID: up.ID, BuiltAt: up.BuiltAt.UTC(), AsOf: at.UTC(),
			Current: replaced == nil})
		moments = append(moments, at)
	}
	held, err := findings.OpenAt(ctx, subject, scope, within, moments)
	if err != nil {
		return nil, err
	}
	for i := range points {
		points[i].Held = held[i]
	}
	slices.Reverse(points)
	return points, nil
}
