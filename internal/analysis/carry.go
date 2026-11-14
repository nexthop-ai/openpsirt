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

// carried is the code finding of the series elsewhere a result new to this build is
// the same result as: the occurrence it takes, and how it was found.
type carried struct {
	occurrence string
	on         string
	// from says where the code finding was found.
	from string
}

// Where a carried occurrence was found.
const (
	// fromParent is a code finding of the branch or tag this one was cut from, on the
	// build of the same variant, paired by the layers on the build's first
	// run of the series.
	fromParent = "parent"
	// fromReopened is a code finding on this build that is closed, found again.
	fromReopened = "reopened"
	// fromSeries is a code finding on another build, on the whole key.
	fromSeries = "series"
)

// carry finds, for each result new to this build, a code finding the series already
// holds that it is the same result as. On the series' first run on the build,
// the code findings open on the parent branch or tag's build of the same variant are paired
// with them layer by layer, which is how a new branch inherits what the line
// it was cut from has decided. Whatever is left is looked up across the
// series, open or closed, on the whole key alone: a probable pairing with a
// code finding the build never saw is a guess. A result found nowhere is absent from
// the answer, and opens an occurrence of its own. An occurrence is carried to
// one result at most, and never one held open on the build, which the run's
// own matching answered.
func carry(ctx context.Context, db bun.IDB, run *series.Run, seriesID int64, first bool, fresh []Keyed,
	held map[string]bool) (map[int]carried, error) {

	out := map[int]carried{}
	if len(fresh) == 0 {
		return out, nil
	}
	if first {
		parent, err := parentBuild(ctx, db, run.BuildID)
		if err != nil {
			return nil, err
		}
		if parent != 0 {
			if err := fromParentBuild(ctx, db, seriesID, parent, fresh, run.FingerprintsChanged, out); err != nil {
				return nil, err
			}
		}
	}
	if err := fromSeriesKey(ctx, db, run.BuildID, seriesID, fresh, held, out); err != nil {
		return nil, err
	}
	return out, nil
}

// parentBuild is the build of the same variant in the branch or tag this build's
// branch or tag was cut from, or zero where there is none.
func parentBuild(ctx context.Context, db bun.IDB, buildID int64) (int64, error) {
	var ids []int64
	err := db.NewSelect().
		TableExpr(`"build" AS "tg"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "tg"."branch_or_tag_id"`).
		Join(`JOIN "build" AS "pt" ON "pt"."branch_or_tag_id" = "s"."parent_id" AND "pt"."variant_id" = "tg"."variant_id"`).
		ColumnExpr(`"pt"."id"`).
		Where(`"tg"."id" = ?`, buildID).
		Scan(ctx, &ids)
	if err != nil {
		return 0, fmt.Errorf("read the build this branch was cut from: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	return ids[0], nil
}

// fromParentBuild pairs the results with the code findings open on the parent build,
// on the unprinted key too where the run's fingerprints differ from that
// build's last.
func fromParentBuild(ctx context.Context, db bun.IDB, seriesID, parent int64, fresh []Keyed, printsChanged bool,
	out map[int]carried) error {
	open, err := series.NewStore(db).Sightings(ctx, kind.Analysis, seriesID, parent)
	if err != nil {
		return err
	}
	candidates, err := candidatesOf(ctx, db, open, fresh)
	if err != nil {
		return fmt.Errorf("read what the branch this was cut from holds open: %w", err)
	}
	layers := pair
	if printsChanged {
		layers = pairAcross
	}
	for _, p := range layers(candidates, fresh) {
		out[p.result] = carried{occurrence: candidates[p.candidate].occurrence, on: p.on, from: fromParent}
	}
	return nil
}

// fromSeriesKey looks the results nothing has carried yet up across the
// series on the whole key. A closed code finding on this build comes first, since
// that is the same result found again here, and then the oldest code finding
// elsewhere. Each result takes the first occurrence neither held open on the
// build nor already carried to another result, so results sharing a key take
// one occurrence each.
func fromSeriesKey(ctx context.Context, db bun.IDB, buildID, seriesID int64, fresh []Keyed, held map[string]bool,
	out map[int]carried) error {
	var keys []string
	wanted := map[string]bool{}
	for i, k := range fresh {
		if _, done := out[i]; !done && !wanted[k.Key] {
			wanted[k.Key] = true
			keys = append(keys, k.Key)
		}
	}
	byKey := map[string][]keyHit{}
	where, args := kind.In(`"f"."kind"`, []kind.Kind{kind.Analysis})
	for start := 0; start < len(keys); start += database.BatchSize {
		end := min(start+database.BatchSize, len(keys))
		var rows []keyHit
		if err := db.NewSelect().
			TableExpr(`"analysis_result" AS "ar"`).
			Join(`JOIN "finding" AS "f" ON "f"."id" = "ar"."finding_id"`).
			Join(`JOIN "sighting" AS "si" ON "si"."finding_id" = "f"."id"`).
			ColumnExpr(`"f"."id", "ar"."match_key", "f"."occurrence_identity", "f"."build_id"`).
			ColumnExpr(`"f"."closed_at", "ar"."start_column"`).
			Where(`"si"."series_id" = ?`, seriesID).
			Where(`"ar"."match_key" IN (?)`, bun.List(keys[start:end])).
			Where(where, args...).
			Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read which code findings of the series these results are: %w", err)
		}
		for _, r := range rows {
			byKey[r.Key] = append(byKey[r.Key], r)
		}
	}
	for k := range byKey {
		hits := byKey[k]
		sort.Slice(hits, func(i, j int) bool {
			a, b := hits[i], hits[j]
			ra, rb := a.BuildID == buildID && a.ClosedAt != nil, b.BuildID == buildID && b.ClosedAt != nil
			if ra != rb {
				return ra
			}
			return a.ID < b.ID
		})
	}
	used := make(map[string]bool, len(held)+len(out))
	for o := range held {
		used[o] = true
	}
	for _, c := range out {
		used[c.occurrence] = true
	}
	// Where a key is held twice, by two results or by two occurrences of the
	// series, a hit at the result's column saying what it says is taken first,
	// so each keeps its occurrence whatever order a run lists them in; the rest
	// take what is left. An occurrence is where its newest code finding was
	// seen, so one message is read for each, never one per build.
	holders := map[string]map[string]bool{}
	for k, hits := range byKey {
		for _, h := range hits {
			holding(holders, k, h.Occurrence)
		}
	}
	var waiting []string
	for i, k := range fresh {
		if _, done := out[i]; !done {
			waiting = append(waiting, k.Key)
		}
	}
	shared := heldTwice(waiting, holders)
	newest := map[string]keyHit{}
	for k := range shared {
		for _, h := range byKey[k] {
			if n, ok := newest[h.Occurrence]; !ok || h.ID > n.ID {
				newest[h.Occurrence] = h
			}
		}
	}
	ids := make([]int64, 0, len(newest))
	for _, h := range newest {
		ids = append(ids, h.ID)
	}
	messages, err := messagesOf(ctx, db, ids)
	if err != nil {
		return err
	}
	var hits []keyHit
	for k := range shared {
		hits = append(hits, byKey[k]...)
	}
	at := bySpot(hits, func(keyHit) bool { return true }, func(h keyHit) spotKey {
		n := newest[h.Occurrence]
		return spotKey{h.Key, spotOf(n.Column, messages[n.ID])}
	})
	take := func(i int, hits []keyHit) {
		for _, h := range hits {
			if used[h.Occurrence] {
				continue
			}
			c := carried{occurrence: h.Occurrence, on: onKey, from: fromSeries}
			if h.BuildID == buildID && h.ClosedAt != nil {
				c.from = fromReopened
			}
			used[h.Occurrence] = true
			out[i] = c
			return
		}
	}
	for i, k := range fresh {
		if _, done := out[i]; !done && shared[k.Key] {
			take(i, at[spotKey{k.Key, spot{k.StartColumn, k.Message}}])
		}
	}
	for i, k := range fresh {
		if _, done := out[i]; !done {
			take(i, byKey[k.Key])
		}
	}
	return nil
}

// keyHit is a code finding of the series holding a key a result holds.
type keyHit struct {
	ID         int64      `bun:"id"`
	Key        string     `bun:"match_key"`
	Occurrence string     `bun:"occurrence_identity"`
	BuildID    int64      `bun:"build_id"`
	ClosedAt   *time.Time `bun:"closed_at"`
	Column     *int       `bun:"start_column"`
}

// messagesOf is what each of these findings last said, by finding.
func messagesOf(ctx context.Context, db bun.IDB, ids []int64) (map[int64]string, error) {
	out := make(map[int64]string, len(ids))
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var rows []struct {
			FindingID int64  `bun:"finding_id"`
			Message   string `bun:"message_text"`
		}
		if err := db.NewSelect().TableExpr(`"analysis_result" AS "ar"`).
			ColumnExpr(`"ar"."finding_id", "ar"."message_text"`).
			Where(`"ar"."finding_id" IN (?)`, bun.List(batch)).Scan(ctx, &rows); err != nil {
			return err
		}
		for _, r := range rows {
			out[r.FindingID] = r.Message
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read what the code findings sharing a key said: %w", err)
	}
	return out, nil
}
