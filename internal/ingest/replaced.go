// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// ErrNotReplaced is a scan no later one of its build replaced, or one of a
// tag.
var ErrNotReplaced = errors.New("the inventory was not replaced")

// Applied narrows a query to scans applied to their build's graph under this
// alias: accepted, with the components counted, which only applying does.
func Applied(q *bun.SelectQuery, alias string) *bun.SelectQuery {
	return q.Where(fmt.Sprintf(`"%[1]s"."status" = ? AND "%[1]s"."components" IS NOT NULL`, alias), Accepted)
}

// Replaced reads one replaced branch inventory and what checking it works
// from.
func (s *Store) Replaced(ctx context.Context, scanID int64) (finding.Replaced, error) {
	var old struct {
		BuildID    int64     `bun:"build_id"`
		ReceivedAt time.Time `bun:"received_at"`
	}
	refused := fmt.Errorf("scan %d: %w", scanID, ErrNotReplaced)
	if err := Applied(s.db.NewSelect().
		TableExpr(`"scan" AS "sc"`).
		Join(`JOIN "build" AS "b" ON "b"."id" = "sc"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "bt" ON "bt"."id" = "b"."branch_or_tag_id"`).
		ColumnExpr(`"sc"."build_id" AS "build_id"`).
		ColumnExpr(`"sc"."received_at" AS "received_at"`).
		Where(`"sc"."id" = ?`, scanID).
		Where(`"bt"."kind" = ?`, catalog.Branch), "sc").
		Scan(ctx, &old); err != nil {
		return finding.Replaced{}, database.FromRead(err, refused, "read the replaced inventory")
	}
	r := finding.Replaced{BuildID: old.BuildID, ScanID: scanID, ArrivedAt: old.ReceivedAt}
	var next struct {
		ID         int64     `bun:"id"`
		ReceivedAt time.Time `bun:"received_at"`
	}
	if err := Applied(s.db.NewSelect().
		TableExpr(`"scan" AS "sc"`).
		ColumnExpr(`"sc"."id" AS "id"`).
		ColumnExpr(`"sc"."received_at" AS "received_at"`).
		Where(`"sc"."build_id" = ?`, old.BuildID).
		Where(`"sc"."id" > ?`, scanID), "sc").
		OrderExpr(`"sc"."id"`).Limit(1).
		Scan(ctx, &next); err != nil {
		return finding.Replaced{}, database.FromRead(err, refused, "read what replaced the inventory")
	}
	r.ReplacementID, r.ReplacedAt = next.ID, next.ReceivedAt

	since, err := finding.LastScanned(ctx, s.db, r.BuildID, r.ArrivedAt, r.ReplacedAt)
	if err != nil {
		return finding.Replaced{}, err
	}
	r.Since = since
	return r, nil
}
