// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// latestClosed reads the most recent closed row of these issues, at each
// component and consumer and at each occurrence identity.
func latestClosed(ctx context.Context, db bun.IDB, buildID int64,
	vulnerabilities []int64) (map[key]Finding, map[at]Finding, error) {

	byKey, byAt := map[key]Finding{}, map[at]Finding{}
	if len(vulnerabilities) == 0 {
		return byKey, byAt, nil
	}
	issues := distinct(vulnerabilities)
	err := database.IDsInBatches(ctx, issues, func(ctx context.Context, batch []int64) error {
		// The latest row of each grouping, by identifier, rather than every
		// closed row ever recorded: an occurrence whose version moves gathers a
		// closed row at every move.
		latest := func(grouping string) *bun.SelectQuery {
			kinds, kindArgs := kind.Closure.Where(`"lf"."kind"`)
			return db.NewSelect().
				TableExpr(`"finding" AS "lf"`).
				ColumnExpr(`MAX("lf"."id")`).
				Where(`"lf"."build_id" = ?`, buildID).
				Where(kinds, kindArgs...).
				Where(`"lf"."closed_at" IS NOT NULL`).
				Where(`"lf"."vulnerability_id" IN (?)`, bun.List(batch)).
				GroupExpr(grouping)
		}
		// A replaced inventory's check writes its rows after the
		// replacement's, so by identifier its match at an occurrence hides the
		// replacement's row there. The latest a scan wrote is read beside it,
		// for the order below to rank.
		scanned := func(grouping string) *bun.SelectQuery {
			return latest(grouping).Where(`NOT (` + checkRecorded("lf") + `)`)
		}
		var rows []Finding
		kinds, kindArgs := kind.Closure.Where(`"kind"`)
		err := db.NewSelect().Model(&rows).
			Column("id", "vulnerability_id", "component_id", "consumer_id",
				"occurrence_identity", "closed_because", "suppressed_by", "unaffected_by", "stated_by").
			// The range again outside the arms: a membership test under OR
			// is never a semi-join on PostgreSQL or MySQL, so without it the
			// read walks every finding in the deployment.
			Where(`"build_id" = ?`, buildID).
			Where(kinds, kindArgs...).
			Where(`"closed_at" IS NOT NULL`).
			Where(`"vulnerability_id" IN (?)`, bun.List(batch)).
			WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
				return q.
					WhereOr(`"id" IN (?)`, latest(`"lf"."vulnerability_id", "lf"."component_id", "lf"."consumer_id"`)).
					WhereOr(`"id" IN (?)`, scanned(`"lf"."vulnerability_id", "lf"."component_id", "lf"."consumer_id"`)).
					WhereOr(`"id" IN (?)`, latest(`"lf"."vulnerability_id", "lf"."occurrence_identity"`))
			}).
			// Ascending, so the last row read at an occurrence is its latest,
			// in the order Later gives: a replaced inventory's check writes
			// its rows after the replacement's, about a stretch before them.
			OrderExpr(`"closed_at" ASC, "id" ASC`).
			Scan(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			byKey[key{row.VulnerabilityID, occurrence{row.ComponentID, value(row.ConsumerID)}}] = row
			byAt[at{row.VulnerabilityID, row.OccurrenceIdentity}] = row
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("read what these occurrences last closed as: %w", err)
	}
	return byKey, byAt, nil
}
