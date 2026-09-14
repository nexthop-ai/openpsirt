package finding

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// What one run of the scanner did.
//
// **The receipt says a run happened; nothing said what it did.** A row reading
// "scanned · 7,604 opened" is a number with no shape: opened *what*, and was
// any of it urgent. Somebody looking at a build that jumped by four thousand
// overnight is asking which of them matter, and the answer was a findings list
// with no way to narrow to that run.
//
// **Read per run rather than stored.** What a run opened is derived from the
// findings that still carry its identifier, so it moves as findings are closed
// and reopened — which is correct, and a stored total would be right at the
// moment the run ended and drift from the list beside it thereafter.

// RanDetail is one scan run, with what it changed.
type RanDetail struct {
	RunID           int64
	Scanner         string
	ScannerVersion  string
	DatabaseVersion string
	RanHere         bool
	StartedAt       time.Time
	FinishedAt      *time.Time
	Failure         string
	Caution         string
	// Opened and Closed are issues at components, the unit every other count
	// here uses: a component reached twenty ways carries the same issue twenty
	// times, and counting rows reports how much the graph shares.
	Opened int
	Closed int
	// OpenedBy and ClosedBy break those down by the rating in force, so
	// "four thousand opened" can be read as the handful that matter and the
	// rest. Keyed by the four words a line ranks on.
	OpenedBy map[string]int
	ClosedBy map[string]int
	// OpenedExploited is how many of what it opened somebody is known to be
	// exploiting. The one number that decides whether a jump is an evening's
	// work or a night's.
	OpenedExploited int
}

// Ran reads one run of the scanner and what it changed.
//
// Narrowed like every other read: the counts carry the reader's visibility,
// because a count is a disclosure with the details removed rather than a
// different kind of answer.
func (s *Store) Ran(ctx context.Context, subject access.Subject,
	targetID, runID int64) (*RanDetail, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	if !subject.Sees(productID) {
		return nil, fmt.Errorf("no build is declared there")
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	var run Run
	// The run has to be this build's. A run identifier from anywhere in the
	// deployment would otherwise be readable through any build the caller
	// holds, with the path doing the authorizing and the identifier doing the
	// reading.
	err = s.db.NewSelect().Model(&run).
		Where("id = ?", runID).Where("target_id = ?", targetID).Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("no such run on this build")
	}
	if err != nil {
		return nil, fmt.Errorf("read that run: %w", err)
	}

	out := &RanDetail{
		RunID: run.ID, Scanner: run.Scanner, ScannerVersion: run.ScannerVersion,
		DatabaseVersion: run.DatabaseVersion, RanHere: run.RanHere,
		StartedAt: run.StartedAt, FinishedAt: run.FinishedAt,
		Failure: run.Failure, Caution: run.Caution,
		OpenedBy: map[string]int{}, ClosedBy: map[string]int{},
	}

	// One statement per direction, each grouped over a distinct inner select
	// rather than COUNT DISTINCT over two columns, which not every engine
	// takes — the same shape the per-run counts on the receipts use, so the
	// receipt and this screen cannot disagree about what a run opened.
	count := func(column string, into map[string]int, exploited *int) error {
		var rows []struct {
			Band      string `bun:"band"`
			Count     int    `bun:"count"`
			Exploited int    `bun:"exploited"`
		}
		inner := s.db.NewSelect().
			Distinct().
			TableExpr(`finding AS "f"`).
			Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
			Join(RatedHere, productID).
			ColumnExpr(BandExpr+` AS "band"`).
			ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
			ColumnExpr(`f.component_id AS "component_id"`).
			ColumnExpr(`CASE WHEN f.urgency >= ? THEN 1 ELSE 0 END AS "exploited"`,
				int64(exploitedBand)).
			Where("f.target_id = ?", targetID).
			Where("f."+column+" = ?", runID).
			Where("f.visibility IN (?)", bun.List(visible))
		err := s.db.NewSelect().
			TableExpr(`(?) AS "changed"`, inner).
			ColumnExpr(`changed.band AS "band"`).
			ColumnExpr(`COUNT(*) AS "count"`).
			ColumnExpr(`SUM(changed.exploited) AS "exploited"`).
			GroupExpr("changed.band").
			Scan(ctx, &rows)
		if err != nil {
			return fmt.Errorf("count what this run changed: %w", err)
		}
		for _, row := range rows {
			into[row.Band] = row.Count
			if exploited != nil {
				*exploited += row.Exploited
			}
		}
		return nil
	}

	if err := count("opened_run_id", out.OpenedBy, &out.OpenedExploited); err != nil {
		return nil, err
	}
	if err := count("closed_run_id", out.ClosedBy, nil); err != nil {
		return nil, err
	}
	for _, n := range out.OpenedBy {
		out.Opened += n
	}
	for _, n := range out.ClosedBy {
		out.Closed += n
	}
	return out, nil
}
