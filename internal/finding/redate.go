// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// checkRecorded is the condition that a row under this alias was written by
// a replaced inventory's check: opened and closed by one run that names the
// inventory it checked.
func checkRecorded(alias string) string {
	return fmt.Sprintf(`"%[1]s"."opened_run_id" = "%[1]s"."closed_run_id"
	AND EXISTS (SELECT 1 FROM "scan_run" AS "cr" WHERE "cr"."id" = "%[1]s"."closed_run_id"
		AND "cr"."checked_scan_id" IS NOT NULL)`, alias)
}

// PublicationUnknown is the condition that a row under this alias is a
// check's match on an issue OSV gives no date and nothing here carried before
// the replacement: opened at the widest window the inventory was current.
//
// Worked out from the issue rather than stored, so a date arriving clears it.
func PublicationUnknown(alias string) string {
	return checkRecorded(alias) + fmt.Sprintf(`
	AND EXISTS (SELECT 1 FROM "vulnerability" AS "uv"
		JOIN "vulnerability" AS "us" ON "us"."id" = "uv"."issue_id"
		WHERE "uv"."id" = "%[1]s"."vulnerability_id"
		AND "us"."published_at" IS NULL AND "us"."first_seen_at" >= "%[1]s"."closed_at")`, alias)
}

// Redated is what a publication date arriving for an issue rewrote.
type Redated struct {
	// Moved is how many rows opened later, and Withdrawn how many were taken
	// back as never exposed.
	Moved, Withdrawn int
}

// Redate rewrites the check's matches on an issue that had no date, now that
// it has one, inside the caller's transaction and before the date is written:
// a date before the replacement moves the opening to the later of that date
// and the inventory's arrival; a date at or after it withdraws the match as
// invalid. Only rows a check wrote are touched, and a row already withdrawn is
// left alone.
func Redate(ctx context.Context, tx bun.IDB, issueID int64, published time.Time) (Redated, error) {
	var out Redated
	var rows []struct {
		ID        int64     `bun:"id"`
		ClosedAt  time.Time `bun:"closed_at"`
		ArrivedAt time.Time `bun:"arrived_at"`
	}
	if err := tx.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "rv" ON "rv"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "scan_run" AS "rr" ON "rr"."id" = "f"."closed_run_id"`).
		Join(`JOIN "scan" AS "rs" ON "rs"."id" = "rr"."checked_scan_id"`).
		ColumnExpr(`"f"."id" AS "id", "f"."closed_at" AS "closed_at", "rs"."received_at" AS "arrived_at"`).
		Where(`"rv"."issue_id" = ?`, issueID).
		Where(PublicationUnknown("f")).
		Where(`COALESCE("f"."closed_because", '') NOT IN (?)`, bun.List(NeverPresent())).
		Scan(ctx, &rows); err != nil {
		return out, fmt.Errorf("read the matches an undated issue opened: %w", err)
	}
	published = published.UTC().Truncate(time.Microsecond)
	opening := map[time.Time][]int64{}
	var withdrawing []int64
	for _, row := range rows {
		if !published.Before(row.ClosedAt) {
			withdrawing = append(withdrawing, row.ID)
			continue
		}
		at := published
		if at.Before(row.ArrivedAt) {
			at = row.ArrivedAt.UTC()
		}
		opening[at] = append(opening[at], row.ID)
	}
	for at, ids := range opening {
		err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewUpdate().Table("finding").Set(`"opened_at" = ?`, at).
				Where(`"id" IN (?)`, bun.List(batch)).Exec(ctx)
			return err
		})
		if err != nil {
			return out, fmt.Errorf("move the opening of %d matches: %w", len(ids), err)
		}
		out.Moved += len(ids)
	}
	err := database.IDsInBatches(ctx, withdrawing, func(ctx context.Context, batch []int64) error {
		_, err := tx.NewUpdate().Table("finding").Set(`"closed_because" = ?`, Invalid).
			Where(`"id" IN (?)`, bun.List(batch)).Exec(ctx)
		return err
	})
	if err != nil {
		return out, fmt.Errorf("withdraw %d matches never exposed: %w", len(withdrawing), err)
	}
	out.Withdrawn = len(withdrawing)
	return out, nil
}
