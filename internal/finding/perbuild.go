// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"github.com/uptrace/bun"
)

// perBuildChunk is how many branches one compound statement joins before the
// next level nests them. SQLite refuses a compound of more than 500 branches,
// and chunks of this size nested once reach 2,500 branches.
const perBuildChunk = 50

// perBuild is one statement reading the rows each build's own queries return,
// every query's under the same columns: one branch per build and query.
//
// A grouping over every build's occurrences at once sorts them together, and
// on a deployment of many builds of one image that sort spills to disk: 3.6
// million open occurrences in 15 builds sorted 573 MB on PostgreSQL. Each
// build grouped in its own branch of a UNION ALL groups in memory, and a
// grouping over the branches reads one row per build and group
// (design-docs/analytics-measurements.md § Many builds).
//
// Branches are nested in chunks of perBuildChunk, each chunk read as a derived
// table of its own, so no compound holds more branches than SQLite accepts.
// The result is nil for no builds.
func perBuild(db bun.IDB, builds []int64, each ...func(build int64) *bun.SelectQuery) *bun.SelectQuery {
	var branches []*bun.SelectQuery
	for _, build := range builds {
		for _, one := range each {
			branches = append(branches, one(build))
		}
	}
	if len(branches) == 0 {
		return nil
	}
	var chunks []*bun.SelectQuery
	for start := 0; start < len(branches); start += perBuildChunk {
		chunk := branches[start]
		for _, branch := range branches[start+1 : min(start+perBuildChunk, len(branches))] {
			chunk = chunk.UnionAll(branch)
		}
		chunks = append(chunks, chunk)
	}
	if len(chunks) == 1 {
		return chunks[0]
	}
	var out *bun.SelectQuery
	for _, chunk := range chunks {
		whole := db.NewSelect().TableExpr(`(?) AS "chunk"`, chunk).ColumnExpr(`"chunk".*`)
		if out == nil {
			out = whole
		} else {
			out = out.UnionAll(whole)
		}
	}
	return out
}
