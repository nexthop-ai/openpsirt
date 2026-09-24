// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// upgradeV030 changes the schema the v0.2.0 release built into v0.3.0's, and
// moves the rows it holds.
//
// The v030 files beside this one hold v0.3.0's declaration of every table this
// changes. A column added is declared as that statement declares it, and what
// is written here is only the order and the rows. Every change is a column
// added, which all four engines make where the table stands, so no table is
// rebuilt.
//
// Three columns, and the rows v0.2.0 left moved onto the rules two of them
// carry:
//
//   - When a recorded flaw was first given a severity in its product. Every
//     recorded flaw rated in force is stamped with the earliest moment one of
//     its places was recorded, which is when the clock v0.2.0 ran started.
//     One rated in no way is left unstamped, and loses its deadline.
//   - Whether a report was found here rather than sent in. Every report
//     v0.2.0 holds is one somebody outside sent: it wrote a report only where
//     somebody said who told us. A recorded flaw with no report at all is one
//     v0.2.0 recorded as found here, so it gives up its disclosure date. It
//     gains no report, because v0.2.0 kept nothing saying who recorded it.
//   - The license an inventory declares for a component. Empty on every row:
//     it is read from an inventory, and the next scan of a build that ships
//     the component writes it, as a supplier is written.
//
// A deadline a recorded flaw holds is rewritten onto the windows for our own
// products as this release ships them, counted from the stamp. Nothing has set
// those windows yet: the settings that hold them arrive with this release. A
// deadline another rule took away stays away.
func upgradeV030(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}

	steps := []func() error{
		// Columns that take a null, which every existing row holds.
		func() error {
			return u.change(findingV030(t), change{table: "finding", add: []added{{column: "rated_at"}}})
		},
		func() error {
			return u.change(componentV030(t), change{table: "component", add: []added{{column: "license"}}})
		},
		// A column whose declared default every existing row takes.
		func() error {
			return u.change(reportV030(t), change{table: "flaw_report", add: []added{{column: "found_here"}}})
		},

		// Rows that move onto the rules the new columns carry.
		func() error { return foundHereLosesItsDate(ctx, tx) },
		func() error { return ratedAndReclocked(ctx, tx) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// foundHereLosesItsDate takes the disclosure date off every recorded flaw no
// report is the record of.
func foundHereLosesItsDate(ctx context.Context, tx bun.Tx) error {
	_, err := tx.NewRaw(`
		UPDATE "finding" SET "disclose_at" = NULL
		WHERE "kind" = ? AND "disclose_at" IS NOT NULL
		  AND "vulnerability_id" NOT IN (
			SELECT "fr"."vulnerability_id" FROM "flaw_report" AS "fr"
			WHERE "fr"."vulnerability_id" IS NOT NULL)`, "entered").Exec(ctx)
	if err != nil {
		return fmt.Errorf("take the disclosure date off a flaw found here: %w", err)
	}
	return nil
}

// ownWindows is how long a recorded flaw may stay open, by how urgent it is,
// as this release ships them. Held here rather than read from the code that
// clocks findings today, because what a migration does is fixed once a release
// has run it.
var ownWindows = map[string]time.Duration{
	"exploited": 7 * 24 * time.Hour,
	"critical":  30 * 24 * time.Hour,
	"high":      90 * 24 * time.Hour,
	"medium":    180 * 24 * time.Hour,
	"low":       365 * 24 * time.Hour,
}

// ownWindow is the window for one severity, folded the way the deadline
// folds it: anything unrecognized is a medium.
func ownWindow(exploited bool, severity string) time.Duration {
	if exploited {
		return ownWindows["exploited"]
	}
	switch severity {
	case "critical", "high":
		return ownWindows[severity]
	case "low", "negligible", "none":
		return ownWindows["low"]
	default:
		return ownWindows["medium"]
	}
}

// ratedAndReclocked stamps each recorded flaw with when it was first rated,
// and rewrites the deadline its open places hold.
//
// Worked out here and written back by identifier. The stamp is the earliest
// recording of the issue in its product, which MySQL will not let an update
// read from the table it is updating.
func ratedAndReclocked(ctx context.Context, tx bun.Tx) error {
	var rows []struct {
		ID        int64      `bun:"id"`
		Issue     int64      `bun:"vulnerability_id"`
		Product   int64      `bun:"product_id"`
		OpenedAt  time.Time  `bun:"opened_at"`
		Open      bool       `bun:"open"`
		Severity  string     `bun:"severity"`
		DueAt     *time.Time `bun:"due_at"`
		Exploited bool       `bun:"exploited"`
		LearnedAt *time.Time `bun:"learned_at"`
	}
	err := tx.NewRaw(`
		SELECT "f"."id" AS "id", "f"."vulnerability_id" AS "vulnerability_id",
			"st"."product_id" AS "product_id", "f"."opened_at" AS "opened_at",
			CASE WHEN "f"."closed_at" IS NULL THEN ? ELSE ? END AS "open",
			COALESCE("ir"."severity", "v"."severity", '') AS "severity",
			"f"."due_at" AS "due_at", "f"."urgency_exploited" AS "exploited",
			"f"."exploited_learned_at" AS "learned_at"
		FROM "finding" AS "f"
		JOIN "target" AS "tg" ON "tg"."id" = "f"."target_id"
		JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"
		JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"
		LEFT JOIN "issue_rating" AS "ir"
		  ON "ir"."vulnerability_id" = "f"."vulnerability_id" AND "ir"."product_id" = "st"."product_id"
		WHERE "f"."kind" = ?`, true, false, "entered").Scan(ctx, &rows)
	if err != nil {
		return fmt.Errorf("read the flaws recorded here: %w", err)
	}

	type flaw struct{ issue, product int64 }
	first := map[flaw]time.Time{}
	for _, row := range rows {
		key := flaw{row.Issue, row.Product}
		if at, seen := first[key]; !seen || row.OpenedAt.Before(at) {
			first[key] = row.OpenedAt
		}
	}

	rated := map[time.Time][]int64{}
	due := map[time.Time][]int64{}
	var none []int64
	for _, row := range rows {
		if row.Severity == "" {
			if row.Open && row.DueAt != nil {
				none = append(none, row.ID)
			}
			continue
		}
		start := first[flaw{row.Issue, row.Product}]
		rated[start] = append(rated[start], row.ID)
		if !row.Open || row.DueAt == nil {
			continue
		}
		from := start
		if row.Exploited && row.LearnedAt != nil && row.LearnedAt.After(from) {
			from = *row.LearnedAt
		}
		at := from.Add(ownWindow(row.Exploited, row.Severity))
		due[at] = append(due[at], row.ID)
	}

	for at, ids := range rated {
		if err := inBatches(ctx, ids, func(batch []int64) error {
			_, err := tx.NewRaw(`UPDATE "finding" SET "rated_at" = ? WHERE "id" IN (?)`,
				at, bun.List(batch)).Exec(ctx)
			return err
		}); err != nil {
			return fmt.Errorf("record when a flaw was first rated: %w", err)
		}
	}
	for at, ids := range due {
		if err := inBatches(ctx, ids, func(batch []int64) error {
			_, err := tx.NewRaw(`UPDATE "finding" SET "due_at" = ? WHERE "id" IN (?)`,
				at, bun.List(batch)).Exec(ctx)
			return err
		}); err != nil {
			return fmt.Errorf("move a recorded flaw onto its own windows: %w", err)
		}
	}
	if err := inBatches(ctx, none, func(batch []int64) error {
		_, err := tx.NewRaw(`UPDATE "finding" SET "due_at" = NULL WHERE "id" IN (?)`,
			bun.List(batch)).Exec(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("take the deadline off a flaw nobody has rated: %w", err)
	}
	return nil
}

// inBatches hands a list of identifiers over a bounded number at a time, so no
// statement binds more parameters than any engine accepts.
func inBatches(ctx context.Context, ids []int64, fn func([]int64) error) error {
	return database.IDsInBatches(ctx, ids, func(_ context.Context, batch []int64) error {
		return fn(batch)
	})
}
