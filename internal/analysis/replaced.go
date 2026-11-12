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
// Read from the build's code findings, each component once, and paired with
// the live components by the name the build stated each under, as the
// inventory's changes pair them: a replaced one by its latest node's, a live
// one by its open node's.
func replacedIn(ctx context.Context, db bun.IDB, buildID int64) (map[int64][]int64, error) {
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	held := db.NewSelect().TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."component_id"`).
		Where(`"f"."build_id" = ?`, buildID).
		Where(kinds, kindArgs...).
		Where(`NOT EXISTS (SELECT 1 FROM "graph_node" AS "ln" WHERE "ln"."build_id" = ?
			AND "ln"."closed_scan_id" IS NULL AND "ln"."component_id" = "f"."component_id")`, buildID).
		Distinct()
	var replaced []struct {
		Component int64  `bun:"component_id"`
		Name      string `bun:"name_folded"`
	}
	if err := db.NewSelect().TableExpr(`(?) AS "h"`, held).
		Join(`JOIN "component" AS "cr" ON "cr"."id" = "h"."component_id"`).
		ColumnExpr(`"cr"."id" AS "component_id"`).
		ColumnExpr(graph.BuildFolded("?", `"cr"."id"`, "cr")+` AS "name_folded"`, buildID).
		Scan(ctx, &replaced); err != nil {
		return nil, fmt.Errorf("read the components build %d no longer holds a code finding sits on: %w", buildID, err)
	}
	if len(replaced) == 0 {
		return map[int64][]int64{}, nil
	}
	var live []struct {
		Component int64  `bun:"component_id"`
		Name      string `bun:"name_folded"`
	}
	if err := db.NewSelect().TableExpr(`"graph_node" AS "nl"`).
		Join(`JOIN "component" AS "cl" ON "cl"."id" = "nl"."component_id"`).
		ColumnExpr(`"cl"."id" AS "component_id", `+graph.NodeFolded("nl", "cl")+` AS "name_folded"`).
		Where(`"nl"."build_id" = ?`, buildID).
		Where(`"nl"."closed_scan_id" IS NULL`).
		Where(`"nl"."is_root" = ?`, false).
		Scan(ctx, &live); err != nil {
		return nil, fmt.Errorf("read the components build %d holds: %w", buildID, err)
	}
	byName := map[string][]int64{}
	for _, one := range live {
		byName[one.Name] = append(byName[one.Name], one.Component)
	}
	out := map[int64][]int64{}
	for _, one := range replaced {
		if named := byName[one.Name]; len(named) > 0 {
			out[one.Component] = named
		}
	}
	return out, nil
}

// beneathOrAdopted is the condition keeping a finding, as "f", at the
// component beneath or anywhere under it, or on a component adopted there.
// The queue never walks from the build's root, whose subtree is the whole
// build and is asked as no narrowing, so the walk starts at the component
// alone.
func beneathOrAdopted(db bun.IDB, buildID, beneath int64, adopted []int64) (string, []any) {
	return `"f"."component_id" IN (?)`, []any{graph.WithinAnd(db, buildID, []int64{beneath}, adopted, false)}
}
