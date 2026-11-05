// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// checksLimit is how many owed checks one pass asks for. Each is a scan of two
// inventories at once, so the queue holds a few hours of them at most.
const checksLimit = 50

// owedChecks asks for every replaced branch inventory whose check is due:
// the newest scanner data is dated at least the settle delay after its
// replacement, and no check of it has finished.
func (s *Schedule) owedChecks(ctx context.Context) (int, error) {
	settle, err := setting.NewStore(s.db.DB).Duration(ctx, setting.CheckSettle, setting.DefaultCheckSettle)
	if err != nil {
		return 0, fmt.Errorf("read how long a replaced inventory waits for its check: %w", err)
	}
	newest, err := newestData(ctx, s.db.DB)
	if err != nil || newest == nil {
		return 0, err
	}
	queued, err := s.queuedOf(ctx, queue.Check)
	if err != nil {
		return 0, err
	}
	if len(queued) >= checksLimit {
		return 0, nil
	}
	cutoff := newest.Add(-settle)

	applied, appliedArgs := `"nx"."status" = ? AND "nx"."components" IS NOT NULL`, ingest.Accepted
	q := ingest.Applied(s.db.NewSelect().
		TableExpr(`"scan" AS "sc"`).
		Join(`JOIN "build" AS "b" ON "b"."id" = "sc"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "bt" ON "bt"."id" = "b"."branch_or_tag_id"`).
		ColumnExpr(`"sc"."id"`).
		Where(`"bt"."kind" = ?`, catalog.Branch).
		Where(`"sc"."replaced_unchecked" = ?`, false), "sc").
		Where(`EXISTS (SELECT 1 FROM "scan" AS "nx"
			WHERE "nx"."build_id" = "sc"."build_id" AND "nx"."id" > "sc"."id"
			AND `+applied+` AND "nx"."received_at" <= ?)`, appliedArgs, cutoff).
		Where(`NOT EXISTS (SELECT 1 FROM "scan_run" AS "cr"
			WHERE "cr"."checked_scan_id" = "sc"."id" AND "cr"."finished_at" IS NOT NULL
			AND COALESCE("cr"."failure", '') = '')`).
		OrderExpr(`"sc"."id" DESC`).
		Limit(int64(checksLimit - len(queued)))
	if len(queued) > 0 {
		q = q.Where(`"sc"."id" NOT IN (?)`, bun.List(queued))
	}
	var owed []int64
	if err := q.Scan(ctx, &owed); err != nil {
		return 0, fmt.Errorf("read which replaced inventories are owed a check: %w", err)
	}
	asked := 0
	for _, scanID := range owed {
		if err := ctx.Err(); err != nil {
			return asked, nil
		}
		_, err := s.queue.Add(ctx, queue.Check, strconv.FormatInt(scanID, 10))
		if errors.Is(err, queue.ErrBacklogFull) {
			return asked, nil
		}
		if err != nil {
			return asked, fmt.Errorf("ask for inventory %d to be checked: %w", scanID, err)
		}
		asked++
	}
	return asked, nil
}

// newestData is the date of the newest vulnerability data any scan here
// matched against, absent before the first.
func newestData(ctx context.Context, db bun.IDB) (*time.Time, error) {
	var runs []finding.Run
	if err := db.NewSelect().Model(&runs).
		Column("database_version", "started_at").
		Where(`"checked_scan_id" IS NULL`).
		Where(`"finished_at" IS NOT NULL`).
		Where(`COALESCE("failure", '') = ''`).
		Order("id DESC").Limit(1).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how new the scanner's data is: %w", err)
	}
	if len(runs) == 0 {
		return nil, nil
	}
	dated := finding.DataDate(runs[0].DatabaseVersion, runs[0].StartedAt)
	return &dated, nil
}
