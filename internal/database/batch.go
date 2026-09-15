package database

import (
	"context"
	"fmt"
	"strings"

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

// InBatchesKeeping inserts rows a bounded number at a time, leaving alone any
// row another writer got to first.
//
// **For a table whose rows are facts rather than somebody's state.** A
// component identified by its content is the same row whoever writes it, so
// two writers describing the same library at the same version are agreeing
// rather than colliding — and the loser of that race had its whole
// transaction fail. Two replicas reading two scans at once is the shipped
// arrangement, and the first time a portfolio meets a shared dependency both
// of them try to write it; one was told its upload could not be read, for a
// component that is now present.
//
// **The caller reads the identifiers back rather than taking them from here.**
// A row somebody else wrote has their identifier and not one this statement
// can report, and a row skipped reports nothing at all — so what the rows say
// afterwards is what a read says, which is the only answer that is true for
// both halves of the set.
//
// One of the few places an engine is asked directly, and it lives here for the
// reason every other such answer does. There is no portable spelling: two of
// them want ON CONFLICT and the other two want INSERT IGNORE.
func InBatchesKeeping[T any](ctx context.Context, db bun.IDB, rows []T) error {
	for start := 0; start < len(rows); start += BatchSize {
		end := min(start+BatchSize, len(rows))
		batch := rows[start:end]
		insert := db.NewInsert().Model(&batch)
		switch db.Dialect().Name().String() {
		case "pg", "sqlite":
			insert = insert.On("CONFLICT DO NOTHING")
		default:
			insert = insert.Ignore()
		}
		if _, err := insert.Exec(ctx); err != nil {
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

// InAnyOf is a membership test over a list too long for one statement.
//
// The same ceiling `IDsInBatches` exists for, met on a read rather than a
// write: a condition cannot be issued in pieces, so the list is split and the
// pieces are OR-ed. Every engine takes that, and each `IN` stays within what
// all four accept.
//
// Answers a condition that is never true for an empty list, which is what an
// empty set means — and what `IN ()` is a syntax error for on two of the four.
func InAnyOf(column string, ids []int64) (string, []any) {
	if len(ids) == 0 {
		return "1 = 0", nil
	}
	said := make([]string, 0, len(ids)/BatchSize+1)
	args := make([]any, 0, len(ids)/BatchSize+1)
	for start := 0; start < len(ids); start += BatchSize {
		end := min(start+BatchSize, len(ids))
		said = append(said, column+" IN (?)")
		args = append(args, bun.List(ids[start:end]))
	}
	return "(" + strings.Join(said, " OR ") + ")", args
}
