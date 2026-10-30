// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// replacedIn is the components a code finding of this build sits on that the
// build no longer holds, each with the live components of the same name it is
// counted at: a code finding keeps the component it opened on, and a rescan at
// a new version replaces the component. A root the build no longer holds is
// left out, since the build's root counts every root it has had.
//
// Read from the build's code findings, each component once.
func replacedIn(ctx context.Context, db bun.IDB, buildID int64) (map[int64][]int64, error) {
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	var rows []struct {
		Replaced int64 `bun:"replaced"`
		Live     int64 `bun:"live"`
	}
	held := db.NewSelect().TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."component_id"`).
		Where(`"f"."build_id" = ?`, buildID).
		Where(kinds, kindArgs...).
		Where(`NOT EXISTS (SELECT 1 FROM "graph_node" AS "ln" WHERE "ln"."build_id" = ?
			AND "ln"."closed_scan_id" IS NULL AND "ln"."component_id" = "f"."component_id")`, buildID).
		Distinct()
	if err := db.NewSelect().TableExpr(`(?) AS "h"`, held).
		Join(`JOIN "component" AS "cr" ON "cr"."id" = "h"."component_id"`).
		Join(`JOIN "component" AS "cl" ON "cl"."name_folded" = "cr"."name_folded"`).
		Join(`JOIN "graph_node" AS "nl" ON "nl"."component_id" = "cl"."id"`).
		ColumnExpr(`"cr"."id" AS "replaced", "cl"."id" AS "live"`).
		Where(`"nl"."build_id" = ?`, buildID).
		Where(`"nl"."closed_scan_id" IS NULL`).
		Where(`"nl"."is_root" = ?`, false).
		Distinct().
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the components build %d no longer holds a code finding sits on: %w", buildID, err)
	}
	out := map[int64][]int64{}
	for _, row := range rows {
		out[row.Replaced] = append(out[row.Replaced], row.Live)
	}
	return out, nil
}

// replacedWithin is the components of replaced whose live namesake is at the
// component beneath or anywhere under it, by the walk the tree counts with.
func replacedWithin(ctx context.Context, db bun.IDB, buildID, beneath int64,
	replaced map[int64][]int64) ([]int64, error) {

	if len(replaced) == 0 {
		return nil, nil
	}
	var namesakes []int64
	for _, live := range replaced {
		namesakes = append(namesakes, live...)
	}
	var within []int64
	if err := db.NewSelect().TableExpr(`(?) AS "w"`, graph.WithinAny(db, buildID, []int64{beneath})).
		ColumnExpr(`"w"."component_id"`).
		Where(`"w"."component_id" IN (?)`, bun.List(namesakes)).
		Scan(ctx, &within); err != nil {
		return nil, fmt.Errorf("read which namesakes of replaced components are beneath component %d of build %d: %w",
			beneath, buildID, err)
	}
	in := map[int64]bool{}
	for _, id := range within {
		in[id] = true
	}
	var out []int64
	for id, live := range replaced {
		for _, l := range live {
			if in[l] {
				out = append(out, id)
				break
			}
		}
	}
	return out, nil
}

// beneathOrAdopted is the condition keeping a finding, as "f", at the
// component beneath or anywhere under it, or on a component adopted there.
func beneathOrAdopted(db bun.IDB, buildID, beneath int64, adopted []int64) (string, []any) {
	within := graph.WithinAny(db, buildID, []int64{beneath})
	if len(adopted) == 0 {
		return `"f"."component_id" IN (?)`, []any{within}
	}
	return `("f"."component_id" IN (?) OR "f"."component_id" IN (?))`, []any{within, bun.List(adopted)}
}
