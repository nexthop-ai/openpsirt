// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// The deadline on a flaw recorded in our own product.

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// ownDeadline is when a recorded flaw has to be answered by, or nothing.
//
// Two things differ from a scanned finding (REQ-33). The windows are the
// product's own, because the fix has to be written rather than taken from
// upstream. And the clock runs from when the flaw was first given a severity
// rather than from when it was recorded, so a flaw nobody has rated carries no
// deadline: there is no urgency yet to set one from.
//
// Everything else is the one rule a scanned finding goes through (Deadline),
// so exploitation and a fix arriving move it the same way.
func ownDeadline(own Windows, severity string, ratedAt *time.Time, state FixState,
	exploited, exploitedHere bool, observedAt time.Time, learnedAt, fixedAt *time.Time,
	floor Floor) *time.Time {

	if severity == "" || ratedAt == nil {
		return nil
	}
	if !floor.Admits(exploited || exploitedHere, severity) {
		return nil
	}
	// Being attacked here admits the finding to the line and moves no window,
	// for the reason Enter gives: how long a fix may take is a question about
	// the work rather than about the attack.
	return Deadline(state, exploited || exploitedHere, *ratedAt, observedAt,
		learnedAt, fixedAt, own.For(exploited, severity))
}

// recountOwn rewrites the deadline on the open recorded flaws of one product,
// narrowed to some issues where any are named.
//
// A recorded flaw given its first severity is stamped as rated here, which is
// the moment its clock starts. The stamp is kept rather than read from the
// rating's history, because a rating withdrawn and made again does not
// restart a clock that was already running.
//
// Row by row rather than grouped into bands the way a scan's findings are.
// Recorded flaws are counted in single or low double digits a year, one row per
// place in each build, so the whole population is small enough that a
// statement per distinct deadline is the simpler shape.
func recountOwn(ctx context.Context, db bun.IDB, productID int64, issues []int64,
	now time.Time) error {

	now = now.UTC().Truncate(time.Microsecond)
	own, err := LoadOwnWindows(ctx, db)
	if err != nil {
		return err
	}
	floor, err := FloorFor(ctx, db, productID)
	if err != nil {
		return err
	}

	var rows []struct {
		ID            int64      `bun:"id"`
		Severity      string     `bun:"severity"`
		RatedAt       *time.Time `bun:"rated_at"`
		FixState      FixState   `bun:"fix_state"`
		FixedAt       *time.Time `bun:"fixed_at"`
		Exploited     bool       `bun:"exploited"`
		ExploitedHere bool       `bun:"exploited_here"`
		LearnedAt     *time.Time `bun:"learned_at"`
	}
	q := db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.Here, productID).
		ColumnExpr(`f.id AS "id"`).
		ColumnExpr(rating.EffectiveExpr+` AS "severity"`).
		ColumnExpr(`f.rated_at AS "rated_at"`).
		ColumnExpr(`f.fix_state AS "fix_state"`).
		ColumnExpr(`f.fixed_at AS "fixed_at"`).
		ColumnExpr(`f.urgency_exploited AS "exploited"`).
		ColumnExpr(`f.urgency_exploited_here AS "exploited_here"`).
		ColumnExpr(`f.exploited_learned_at AS "learned_at"`).
		Where("f.kind = ?", Entered).
		Where("f.closed_at IS NULL").
		Where("st.product_id = ?", productID)
	if len(issues) > 0 {
		q = q.Where("f.vulnerability_id IN (?)", bun.List(issues))
	}
	if err := q.Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read the flaws recorded here: %w", err)
	}

	var firstRated []int64
	due := map[time.Time][]int64{}
	var none []int64
	for _, row := range rows {
		if row.Severity != "" && row.RatedAt == nil {
			firstRated = append(firstRated, row.ID)
			at := now
			row.RatedAt = &at
		}
		at := ownDeadline(own, row.Severity, row.RatedAt, row.FixState,
			row.Exploited, row.ExploitedHere, now, row.LearnedAt, row.FixedAt, floor)
		if at == nil {
			none = append(none, row.ID)
			continue
		}
		due[*at] = append(due[*at], row.ID)
	}

	if err := database.IDsInBatches(ctx, firstRated, func(ctx context.Context, batch []int64) error {
		_, err := db.NewUpdate().Model((*Finding)(nil)).
			Set("rated_at = ?", now).
			Where("id IN (?)", bun.List(batch)).
			Where("rated_at IS NULL").
			Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("record when these were first rated: %w", err)
	}
	for at, ids := range due {
		if err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			_, err := db.NewUpdate().Model((*Finding)(nil)).
				Set("due_at = ?", at).
				Where("id IN (?)", bun.List(batch)).
				Exec(ctx)
			return err
		}); err != nil {
			return fmt.Errorf("rewrite the deadline on a recorded flaw: %w", err)
		}
	}
	// A second statement rather than a CASE choosing between NULL and a
	// parameter, which leaves one engine nothing to infer the column's type
	// from.
	if err := database.IDsInBatches(ctx, none, func(ctx context.Context, batch []int64) error {
		_, err := db.NewUpdate().Model((*Finding)(nil)).
			Set("due_at = NULL").
			Where("id IN (?)", bun.List(batch)).
			Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("take the deadline off a recorded flaw: %w", err)
	}
	return nil
}
