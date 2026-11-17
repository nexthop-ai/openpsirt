// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Reads over every build of a product group the findings in chunks of builds,
// each chunk a branch of one UNION ALL, and group the branches' rows once.
//
// One grouping over every build's findings sorts them all at once, and on a
// deployment of many builds of one image that sort spills to disk: 3.6 million
// open findings in 15 builds sorted 573 MB on PostgreSQL. A chunk holds about
// as many findings as one build of a real image, so each branch groups in
// memory, and a deployment of many small builds is one chunk, grouped as one
// statement (design-docs/analytics-measurements.md § Many builds).
const (
	// shippedChunkRows is how many findings a chunk holds before the next
	// starts: a third of one build of a real switch image, which groups in
	// memory.
	shippedChunkRows = 100_000
	// mostChunks is the most chunks one read makes. A deployment holding more
	// findings than this many chunks of shippedChunkRows has larger chunks,
	// so no statement holds more than this many branches a part.
	mostChunks = 50
)

// buildHolding is one build and how many findings it holds that a read can
// return.
type buildHolding struct {
	BuildID int64 `bun:"build_id"`
	Rows    int64 `bun:"rows"`
}

// holding is, of these builds, each that holds a finding meeting a condition,
// with how many. A build holding none is left out, so a retired or empty build
// costs a read nothing.
//
// The condition is on the columns the group index holds, so the count reads no
// table row: 3.6 million open findings in 15 builds count in 85 ms on
// PostgreSQL.
func (s *Store) holding(ctx context.Context, builds []int64, where string, args ...any) ([]buildHolding, error) {
	var out []buildHolding
	for start := 0; start < len(builds); start += database.BatchSize {
		var read []buildHolding
		q := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			ColumnExpr(`"f"."build_id" AS "build_id"`).
			ColumnExpr(`COUNT(*) AS "rows"`).
			Where(`"f"."build_id" IN (?)`, bun.List(builds[start:min(start+database.BatchSize, len(builds))])).
			Where(where, args...).
			GroupExpr(`"f"."build_id"`).
			OrderExpr(`"f"."build_id"`)
		if err := q.Scan(ctx, &read); err != nil {
			return nil, fmt.Errorf("count what each build holds: %w", err)
		}
		out = append(out, read...)
	}
	return out, nil
}

// chunked packs the builds, in order, into chunks of about chunkRows findings
// each: a build holding more is a chunk of its own, and builds holding fewer
// share one. Where the findings would make more than mostChunks chunks, each
// chunk holds more, so there are never more than mostChunks.
func chunked(held []buildHolding, chunkRows int64) [][]int64 {
	if chunkRows <= 0 {
		chunkRows = shippedChunkRows
	}
	var total int64
	for _, h := range held {
		total += h.Rows
	}
	// Two neighboring chunks together always hold more than the bound, so a
	// bound of twice the share keeps the chunks to mostChunks.
	if share := (2*total + mostChunks - 2) / (mostChunks - 1); share > chunkRows {
		chunkRows = share
	}
	var out [][]int64
	var current []int64
	var rows int64
	for _, h := range held {
		if len(current) > 0 && rows+h.Rows > chunkRows {
			out = append(out, current)
			current, rows = nil, 0
		}
		current = append(current, h.BuildID)
		rows += h.Rows
	}
	if len(current) > 0 {
		out = append(out, current)
	}
	return out
}

// chunks is the builds a read groups, in chunks: those of these builds holding
// a finding meeting the condition. The condition is one every row the read
// returns meets, so a build left out holds nothing the read would return.
func (s *Store) chunks(ctx context.Context, builds []int64, where string, args ...any) ([][]int64, error) {
	held, err := s.holding(ctx, builds, where, args...)
	if err != nil {
		return nil, err
	}
	return chunked(held, s.chunkRows), nil
}

// perChunk is one statement reading the rows each chunk's queries return,
// every query's under the same columns: one branch per chunk and query. The
// result is nil for no chunks.
func perChunk(chunks [][]int64, each ...func(builds []int64) *bun.SelectQuery) *bun.SelectQuery {
	var out *bun.SelectQuery
	for _, chunk := range chunks {
		for _, one := range each {
			if out == nil {
				out = one(chunk)
			} else {
				out = out.UnionAll(one(chunk))
			}
		}
	}
	return out
}
