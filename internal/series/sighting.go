// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// Sighting is what a series knows of one finding it reports: the run that
// first saw it, the last that did, and the first comparable run that did not.
type Sighting struct {
	bun.BaseModel `bun:"table:sighting,alias:si"`

	ID          int64  `bun:"id,pk,autoincrement"`
	FindingID   int64  `bun:"finding_id,notnull"`
	SeriesID    int64  `bun:"series_id,notnull"`
	FirstRunID  int64  `bun:"first_run_id,notnull"`
	LastRunID   int64  `bun:"last_run_id,notnull"`
	AbsentRunID *int64 `bun:"absent_run_id"`
	// FixedRunID is the run whose build a person stated the finding fixed
	// in, once they closed it as fixed.
	FixedRunID *int64 `bun:"fixed_run_id"`
}

// Sightings is the open findings of a kind a series reports against one build,
// with what the series knows of each.
func (s *Store) Sightings(ctx context.Context, k kind.Kind, seriesID, targetID int64) ([]Sighting, error) {
	var held []Sighting
	where, args := kind.In(`"f"."kind"`, []kind.Kind{k})
	err := s.db.NewSelect().Model(&held).
		Join(`JOIN "finding" AS "f" ON "f"."id" = "si"."finding_id"`).
		Where(`"si"."series_id" = ?`, seriesID).
		Where(`"f"."target_id" = ?`, targetID).
		Where(`"f"."closed_at" IS NULL`).
		Where(where, args...).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read what the series holds open on the build: %w", err)
	}
	return held, nil
}

// Saw records that a run saw these findings: first seen here where the series
// had not seen them, and present again where it had.
func (s *Store) Saw(ctx context.Context, run *Run, findingIDs []int64) error {
	if len(findingIDs) == 0 {
		return nil
	}
	var known []int64
	if err := database.IDsInBatches(ctx, findingIDs, func(ctx context.Context, batch []int64) error {
		var some []int64
		if err := s.db.NewSelect().Model((*Sighting)(nil)).Column("finding_id").
			Where(`"finding_id" IN (?)`, bun.List(batch)).Scan(ctx, &some); err != nil {
			return err
		}
		known = append(known, some...)
		return nil
	}); err != nil {
		return fmt.Errorf("read which findings the series has seen: %w", err)
	}
	if err := database.IDsInBatches(ctx, known, func(ctx context.Context, batch []int64) error {
		_, err := s.db.NewUpdate().Model((*Sighting)(nil)).
			Set(`"last_run_id" = ?`, run.ID).
			Set(`"absent_run_id" = NULL`).
			Where(`"finding_id" IN (?)`, bun.List(batch)).Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("record that the run saw them again: %w", err)
	}
	seen := make(map[int64]bool, len(known))
	for _, id := range known {
		seen[id] = true
	}
	var fresh []Sighting
	for _, id := range findingIDs {
		if !seen[id] {
			seen[id] = true
			fresh = append(fresh, Sighting{
				FindingID: id, SeriesID: run.SeriesID, FirstRunID: run.ID, LastRunID: run.ID,
			})
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	if err := database.InBatchesUnkeyed(ctx, s.db, fresh); err != nil {
		return fmt.Errorf("record what the run saw first: %w", err)
	}
	return nil
}

// Missed records the first comparable run that did not see these findings.
// A finding already recorded as missed keeps the run that missed it first.
func (s *Store) Missed(ctx context.Context, run *Run, findingIDs []int64) error {
	return database.IDsInBatches(ctx, findingIDs, func(ctx context.Context, batch []int64) error {
		_, err := s.db.NewUpdate().Model((*Sighting)(nil)).
			Set(`"absent_run_id" = ?`, run.ID).
			Where(`"finding_id" IN (?)`, bun.List(batch)).
			Where(`"absent_run_id" IS NULL`).Exec(ctx)
		if err != nil {
			return fmt.Errorf("record that the run did not see them: %w", err)
		}
		return nil
	})
}
