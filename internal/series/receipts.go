// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package series

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// Sent is one run as its receipt: the run, and the name of its series.
type Sent struct {
	Run
	SeriesName string
}

// Receipts is what became of the runs of a kind sent against one build,
// newest first, with how many there are.
//
// A key reads them for a build it may send to. A person reads them where they
// read the kind's findings at the visibility it opens at, because a receipt
// counts them.
func (s *Store) Receipts(ctx context.Context, subject access.Subject, productID, targetID int64,
	k kind.Kind, opensAt access.Visibility, limit, offset int) ([]Sent, int, error) {

	if err := catalog.ReadsBuild(ctx, s.db, subject, targetID); err != nil {
		return nil, 0, err
	}
	if subject.Kind != access.Pipeline && !subject.Reads(opensAt, productID) {
		return nil, 0, access.Denied(fmt.Sprintf("read what analyzers sent against product %d", productID))
	}
	limit = database.AList.Of(limit)
	total, err := s.db.NewSelect().Model((*Run)(nil)).
		Join(`JOIN "series" AS "se" ON "se"."id" = "sr"."series_id"`).
		Where(`"sr"."target_id" = ?`, targetID).
		Where(`"se"."kind" = ?`, k).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count the runs sent: %w", err)
	}
	var runs []Run
	if err := s.db.NewSelect().Model(&runs).
		Join(`JOIN "series" AS "se" ON "se"."id" = "sr"."series_id"`).
		Where(`"sr"."target_id" = ?`, targetID).
		Where(`"se"."kind" = ?`, k).
		OrderExpr(`"sr"."received_at" DESC, "sr"."id" DESC`).
		Limit(int64(limit)).Offset(int64(offset)).
		Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("read the runs sent: %w", err)
	}
	ids := make([]int64, 0, len(runs))
	for _, r := range runs {
		ids = append(ids, r.SeriesID)
	}
	names := map[int64]string{}
	if len(ids) > 0 {
		var held []Series
		if err := s.db.NewSelect().Model(&held).
			Where(`"se"."id" IN (?)`, bun.List(ids)).Scan(ctx); err != nil {
			return nil, 0, fmt.Errorf("read the series the runs belong to: %w", err)
		}
		for _, h := range held {
			names[h.ID] = h.Name
		}
	}
	sent := make([]Sent, len(runs))
	for i, r := range runs {
		sent[i] = Sent{Run: r, SeriesName: names[r.SeriesID]}
	}
	return sent, int(total), nil
}
