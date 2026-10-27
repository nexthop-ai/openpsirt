// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// carried is the lead of the series elsewhere a result new to this build is
// the same result as: the occurrence it takes, and how it was found.
type carried struct {
	occurrence string
	on         string
	// from says where the lead was found.
	from string
}

// Where a carried occurrence was found.
const (
	// fromParent is a lead of the stream this one was cut from, on the
	// build of the same variant, paired by the layers on the build's first
	// run of the series.
	fromParent = "parent"
	// fromReopened is a lead on this build that is closed, found again.
	fromReopened = "reopened"
	// fromSeries is a lead on another build, on the whole key.
	fromSeries = "series"
)

// carry finds, for each result new to this build, a lead the series already
// holds that it is the same result as. On the series' first run on the build,
// the leads open on the parent stream's build of the same variant are paired
// with them layer by layer, which is how a new branch inherits what the line
// it was cut from has decided. Whatever is left is looked up across the
// series, open or closed, on the whole key alone: a probable pairing with a
// lead the build never saw is a guess. A result found nowhere is absent from
// the answer, and opens an occurrence of its own.
func carry(ctx context.Context, db bun.IDB, run *series.Run, seriesID int64, first bool, fresh []Keyed) (
	map[int]carried, error) {

	out := map[int]carried{}
	if len(fresh) == 0 {
		return out, nil
	}
	if first {
		parent, err := parentBuild(ctx, db, run.TargetID)
		if err != nil {
			return nil, err
		}
		if parent != 0 {
			if err := fromParentBuild(ctx, db, seriesID, parent, fresh, run.FingerprintsChanged, out); err != nil {
				return nil, err
			}
		}
	}
	if err := fromSeriesKey(ctx, db, run.TargetID, seriesID, fresh, out); err != nil {
		return nil, err
	}
	return out, nil
}

// parentBuild is the build of the same variant in the stream this build's
// stream was cut from, or zero where there is none.
func parentBuild(ctx context.Context, db bun.IDB, targetID int64) (int64, error) {
	var ids []int64
	err := db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "s" ON "s"."id" = "tg"."stream_id"`).
		Join(`JOIN "target" AS "pt" ON "pt"."stream_id" = "s"."parent_id" AND "pt"."variant_id" = "tg"."variant_id"`).
		ColumnExpr(`"pt"."id"`).
		Where(`"tg"."id" = ?`, targetID).
		Scan(ctx, &ids)
	if err != nil {
		return 0, fmt.Errorf("read the build this branch was cut from: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	return ids[0], nil
}

// fromParentBuild pairs the results with the leads open on the parent build,
// on the unprinted key too where the run's fingerprints differ from that
// build's last.
func fromParentBuild(ctx context.Context, db bun.IDB, seriesID, parent int64, fresh []Keyed, printsChanged bool,
	out map[int]carried) error {
	open, err := series.NewStore(db).Sightings(ctx, kind.Analysis, seriesID, parent)
	if err != nil {
		return err
	}
	absent := make(map[int64]bool, len(open))
	ids := make([]int64, 0, len(open))
	for _, s := range open {
		ids = append(ids, s.FindingID)
		absent[s.FindingID] = s.AbsentRunID != nil
	}
	candidates, err := candidatesOf(ctx, db, ids, absent)
	if err != nil {
		return fmt.Errorf("read what the branch this was cut from holds open: %w", err)
	}
	occurrences, err := occurrencesOf(ctx, db, ids)
	if err != nil {
		return err
	}
	layers := pair
	if printsChanged {
		layers = pairAcross
	}
	for _, p := range layers(candidates, fresh) {
		id := candidates[p.candidate].findingID
		out[p.result] = carried{occurrence: occurrences[id], on: p.on, from: fromParent}
	}
	return nil
}

// occurrencesOf is the occurrence each of these findings is at.
func occurrencesOf(ctx context.Context, db bun.IDB, ids []int64) (map[int64]string, error) {
	out := make(map[int64]string, len(ids))
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var rows []struct {
			ID         int64  `bun:"id"`
			Occurrence string `bun:"occurrence_identity"`
		}
		if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
			ColumnExpr(`"f"."id", "f"."occurrence_identity"`).
			Where(`"f"."id" IN (?)`, bun.List(batch)).Scan(ctx, &rows); err != nil {
			return err
		}
		for _, r := range rows {
			out[r.ID] = r.Occurrence
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read where these leads are: %w", err)
	}
	return out, nil
}

// fromSeriesKey looks the results nothing has carried yet up across the
// series on the whole key. A closed lead on this build comes first, since
// that is the same result found again here, and then the oldest lead
// elsewhere.
func fromSeriesKey(ctx context.Context, db bun.IDB, targetID, seriesID int64, fresh []Keyed, out map[int]carried) error {
	var keys []string
	wanted := map[string]bool{}
	for i, k := range fresh {
		if _, done := out[i]; !done && !wanted[k.Key] {
			wanted[k.Key] = true
			keys = append(keys, k.Key)
		}
	}
	type held struct {
		ID         int64      `bun:"id"`
		Key        string     `bun:"match_key"`
		Occurrence string     `bun:"occurrence_identity"`
		TargetID   int64      `bun:"target_id"`
		ClosedAt   *time.Time `bun:"closed_at"`
	}
	byKey := map[string][]held{}
	where, args := kind.In(`"f"."kind"`, []kind.Kind{kind.Analysis})
	for start := 0; start < len(keys); start += database.BatchSize {
		end := min(start+database.BatchSize, len(keys))
		var rows []held
		if err := db.NewSelect().
			TableExpr(`"analysis_result" AS "ar"`).
			Join(`JOIN "finding" AS "f" ON "f"."id" = "ar"."finding_id"`).
			Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
			ColumnExpr(`"f"."id", "ar"."match_key", "f"."occurrence_identity", "f"."target_id"`).
			ColumnExpr(`"f"."closed_at"`).
			Where(`"si"."series_id" = ?`, seriesID).
			Where(`"ar"."match_key" IN (?)`, bun.List(keys[start:end])).
			Where(where, args...).
			Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read which leads of the series these results are: %w", err)
		}
		for _, r := range rows {
			byKey[r.Key] = append(byKey[r.Key], r)
		}
	}
	for k := range byKey {
		hits := byKey[k]
		sort.Slice(hits, func(i, j int) bool {
			a, b := hits[i], hits[j]
			ra, rb := a.TargetID == targetID && a.ClosedAt != nil, b.TargetID == targetID && b.ClosedAt != nil
			if ra != rb {
				return ra
			}
			return a.ID < b.ID
		})
	}
	for i, k := range fresh {
		hits := byKey[k.Key]
		if _, done := out[i]; done || len(hits) == 0 {
			continue
		}
		c := carried{occurrence: hits[0].Occurrence, on: onKey, from: fromSeries}
		if hits[0].TargetID == targetID && hits[0].ClosedAt != nil {
			c.from = fromReopened
		}
		out[i] = c
	}
	return nil
}
