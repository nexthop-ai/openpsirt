// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// BuiltTrend is the trend over a scope by build date, oldest first: one point
// for each of the latest limit steps, a day or a week, that holds the build
// time an upload in the scope states.
//
// At a step's end each build is read as its newest upload built by then
// leaves it. An inventory is current from its arrival until the next applied
// one arrives, as the replaced-inventory check reads it. A replaced inventory
// is read at the start of the last successful scan of its build, other than a
// check, that started while it was current: what was known of it then, never
// rescanned against today's data. The inventory a build holds is read now. An
// inventory no scan reached is passed over, so its build is read as the upload
// before it left it.
//
// Steps end at midnight UTC, the last at the coming one, as the calendar
// trend's do, and a point is dated by its step's last day.
func (s *Store) BuiltTrend(ctx context.Context, subject access.Subject, scope finding.Scope,
	within finding.Within, step time.Duration, limit int) ([]finding.Point, error) {

	limit = database.APlot.Of(limit)
	findings := finding.NewStore(s.db)
	builds, err := findings.TrendBuilds(ctx, subject, scope)
	if err != nil || len(builds) == 0 {
		return nil, err
	}

	type upload struct {
		BuildID    int64     `bun:"build_id"`
		BuiltAt    time.Time `bun:"built_at"`
		ReceivedAt time.Time `bun:"received_at"`
		read       time.Time
	}
	// Every build's uploads, in the order they apply, which is build time.
	var uploads []upload
	for start := 0; start < len(builds); start += database.BatchSize {
		var part []upload
		if err := Applied(s.db.NewSelect().
			TableExpr(`"scan" AS "sc"`).
			ColumnExpr(`"sc"."build_id" AS "build_id"`).
			ColumnExpr(`"sc"."built_at" AS "built_at"`).
			ColumnExpr(`"sc"."received_at" AS "received_at"`).
			Where(`"sc"."build_id" IN (?)`, bun.List(builds[start:min(start+database.BatchSize, len(builds))])), "sc").
			OrderExpr(`"sc"."build_id", "sc"."id"`).
			Scan(ctx, &part); err != nil {
			return nil, fmt.Errorf("read the uploads in scope: %w", err)
		}
		uploads = append(uploads, part...)
	}
	if len(uploads) == 0 {
		return nil, nil
	}

	// The scans of those builds since the earliest upload arrived.
	earliest := uploads[0].ReceivedAt
	for _, u := range uploads {
		if u.ReceivedAt.Before(earliest) {
			earliest = u.ReceivedAt
		}
	}
	runsOf := map[int64][]time.Time{}
	for start := 0; start < len(builds); start += database.BatchSize {
		var runs []finding.Run
		if err := s.db.NewSelect().Model(&runs).
			Column("build_id", "started_at").
			Where(`"build_id" IN (?)`, bun.List(builds[start:min(start+database.BatchSize, len(builds))])).
			Where(`"checked_scan_id" IS NULL`).
			Where(`"finished_at" IS NOT NULL`).
			Where(`COALESCE("failure", '') = ''`).
			Where(`"started_at" >= ?`, earliest).
			Order("started_at ASC", "id ASC").
			Scan(ctx); err != nil {
			return nil, fmt.Errorf("read the scans in scope: %w", err)
		}
		for _, run := range runs {
			runsOf[run.BuildID] = append(runsOf[run.BuildID], run.StartedAt)
		}
	}

	// Each upload's moment, keeping only those a scan reached.
	now := s.now().UTC()
	byBuild := map[int64][]upload{}
	for i, u := range uploads {
		current := i+1 == len(uploads) || uploads[i+1].BuildID != u.BuildID
		var last *time.Time
		for _, started := range runsOf[u.BuildID] {
			if started.Before(u.ReceivedAt) {
				continue
			}
			if !current && !started.Before(uploads[i+1].ReceivedAt) {
				break
			}
			last = &started
		}
		if last == nil {
			continue
		}
		u.read = *last
		if current {
			u.read = now
		}
		byBuild[u.BuildID] = append(byBuild[u.BuildID], u)
	}

	// The steps holding a build time, the latest limit of them.
	end := now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	stepEnd := func(at time.Time) time.Time {
		back := end.Sub(at) / step
		return end.Add(-back * step)
	}
	held := map[time.Time]bool{}
	for _, ups := range byBuild {
		for _, u := range ups {
			held[stepEnd(u.BuiltAt)] = true
		}
	}
	var ends []time.Time
	for at := range held {
		ends = append(ends, at)
	}
	sort.Slice(ends, func(i, j int) bool { return ends[i].Before(ends[j]) })
	if len(ends) > limit {
		ends = ends[len(ends)-limit:]
	}

	readings := make([]finding.Reading, len(ends))
	for k, at := range ends {
		r := finding.Reading{At: at, Builds: map[int64]time.Time{}, First: map[int64]bool{}}
		for build, ups := range byBuild {
			// The newest upload built by the step's end.
			n := sort.Search(len(ups), func(i int) bool { return ups[i].BuiltAt.After(at) })
			if n == 0 {
				continue
			}
			r.Builds[build] = ups[n-1].read
			// Its first upload, read here and at no reading before.
			if n == 1 {
				before := false
				if k > 0 {
					_, before = readings[k-1].Builds[build]
				}
				r.First[build] = !before
			}
		}
		readings[k] = r
	}
	return findings.TrendAtReadings(ctx, subject, scope, within, readings)
}
