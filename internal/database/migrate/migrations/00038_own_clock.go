// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationNoTxContext(upOwnClock, downOwnClock)
}

// A flaw recorded here is clocked from its first severity on windows of its
// own (REQ-33), and only one reported from outside carries a disclosure date
// (REQ-37).
//
// Two columns, and the rows v0.2.0 left moved onto the rules they carry:
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
//
// A deadline a recorded flaw holds is rewritten onto the windows for our own
// products as this release ships them, counted from the stamp. Nothing has set
// those windows yet: the settings that hold them arrive with this release. A
// deadline another rule took away stays away.
//
// Registered without the library's transaction and run in one of its own, so
// that the rows are read and written through the query builder, which binds a
// value the same way on every engine.
func upOwnClock(ctx context.Context, sqldb *sql.DB) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	db, err := database.Query(sqldb, migrate.EngineFrom(ctx))
	if err != nil {
		return err
	}
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for _, statement := range []string{
			// Null on a scanned row, whose clock runs from its opening, and
			// on a recorded flaw nobody has rated, which has no clock.
			`ALTER TABLE "finding" ADD COLUMN "rated_at" ` + t.timestamp + ` NULL`,
			// A default rather than a fill, because a report is from outside
			// unless somebody says otherwise, which is also what a row
			// written before this column is.
			`ALTER TABLE "flaw_report" ADD COLUMN "found_here" ` + t.boolean + ` DEFAULT FALSE NOT NULL`,
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("%s: %w", firstLine(statement), err)
			}
		}
		if err := foundHereLosesItsDate(ctx, tx); err != nil {
			return err
		}
		return ratedAndReclocked(ctx, tx)
	})
}

// downOwnClock takes the two columns away. A deadline and a disclosure date
// the upgrade moved stay where it moved them: v0.2.0 reads both columns as it
// always did, and what they held before is not kept.
func downOwnClock(ctx context.Context, sqldb *sql.DB) error {
	db, err := database.Query(sqldb, migrate.EngineFrom(ctx))
	if err != nil {
		return err
	}
	return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		for _, statement := range []string{
			`ALTER TABLE "flaw_report" DROP COLUMN "found_here"`,
			`ALTER TABLE "finding" DROP COLUMN "rated_at"`,
		} {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("%s: %w", firstLine(statement), err)
			}
		}
		return nil
	})
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
