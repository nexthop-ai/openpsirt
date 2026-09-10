package database

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

// BatchSize is how many rows one statement carries.
//
// Two of the four engines cap how large a single statement may be, the cap is
// server configuration rather than anything a client can discover, and the
// lowest default in circulation is sixteen megabytes. One real image produces
// over three hundred thousand findings in a single run; sent as one statement
// that is tens of megabytes of SQL, which fails on those two and holds the
// whole set in memory on all four.
//
// The number is small enough that a batch stays far inside every default and
// large enough that the round trips do not dominate.
const BatchSize = 500

// InBatches inserts rows a bounded number at a time.
func InBatches[T any](ctx context.Context, db bun.IDB, rows []T) error {
	for start := 0; start < len(rows); start += BatchSize {
		end := min(start+BatchSize, len(rows))
		batch := rows[start:end]
		if _, err := db.NewInsert().Model(&batch).Exec(ctx); err != nil {
			return fmt.Errorf("insert rows %d to %d: %w", start, end, err)
		}
	}
	return nil
}

// IDsInBatches calls fn with the identifiers a bounded number at a time.
//
// A list of identifiers in a statement has the same ceiling as a list of rows,
// and closing what a scan no longer contains can name as many of them as
// opening did.
func IDsInBatches(ctx context.Context, ids []int64, fn func(context.Context, []int64) error) error {
	for start := 0; start < len(ids); start += BatchSize {
		end := min(start+BatchSize, len(ids))
		if err := fn(ctx, ids[start:end]); err != nil {
			return err
		}
	}
	return nil
}
