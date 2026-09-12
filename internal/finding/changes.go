package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Change is what one run of the scanner altered.
//
// Counted as issues at components rather than as places, which is how every
// other number in this tool counts. A component reached twenty ways carries
// the same issue twenty times, so counting rows reports how much the
// dependency graph shares rather than how much changed — the mistake that
// reported 441,108 open where 5,661 issues were open, and made a release chart
// disagree with the list beside it by two orders of magnitude.
type Change struct {
	Opened int
	Closed int
}

// Changes reports what each of these runs opened and closed.
//
// A run that changed nothing is absent from the answer rather than present as
// a zero, because a rebuild that finds exactly what the last one found is the
// ordinary case and writing nothing is what the storage does.
func (s *Store) Changes(ctx context.Context, subject access.Subject, targetID int64,
	runIDs []int64) (map[int64]Change, error) {

	if len(runIDs) == 0 {
		return map[int64]Change{}, nil
	}
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	if !subject.Sees(productID) {
		return nil, fmt.Errorf("no build is declared there")
	}
	// Counts carry the reader's visibility like every other read does. A
	// run that opened an undisclosed finding must not report a larger
	// number to somebody who cannot see it — a count is a disclosure with
	// the details removed rather than a different kind of answer.
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return map[int64]Change{}, nil
	}

	// A run this reader may count is in the map whatever it changed, so that a
	// caller can tell a run that changed nothing from a run it may not count.
	// Answered here rather than by the caller asking the access package a
	// second question: what a reader may count is this store's rule, and the
	// two spellings would drift.
	out := make(map[int64]Change, len(runIDs))
	for _, id := range runIDs {
		out[id] = Change{}
	}
	// One statement per direction rather than one per run: a page of fifty
	// receipts would otherwise be a hundred round trips to fill two columns.
	count := func(column string, into func(*Change, int)) error {
		var rows []struct {
			RunID int64 `bun:"run_id"`
			Count int   `bun:"count"`
		}
		// Grouped over a distinct inner select rather than COUNT DISTINCT over
		// two columns, which not every engine takes.
		inner := s.db.NewSelect().
			Distinct().
			TableExpr("finding AS f").
			ColumnExpr("f."+column+" AS run_id").
			ColumnExpr("f.vulnerability_id AS vulnerability_id").
			ColumnExpr("f.component_id AS component_id").
			Where("f.target_id = ?", targetID).
			Where("f."+column+" IN (?)", bun.List(runIDs)).
			Where("f.visibility IN (?)", bun.List(visible))
		err := s.db.NewSelect().
			TableExpr(`(?) AS "changed"`, inner).
			ColumnExpr("changed.run_id AS run_id").
			ColumnExpr("COUNT(*) AS count").
			GroupExpr("changed.run_id").
			Scan(ctx, &rows)
		if err != nil {
			return fmt.Errorf("count what a run changed: %w", err)
		}
		for _, row := range rows {
			change := out[row.RunID]
			into(&change, row.Count)
			out[row.RunID] = change
		}
		return nil
	}

	if err := count("opened_run_id", func(c *Change, n int) { c.Opened = n }); err != nil {
		return nil, err
	}
	if err := count("closed_run_id", func(c *Change, n int) { c.Closed = n }); err != nil {
		return nil, err
	}
	return out, nil
}
