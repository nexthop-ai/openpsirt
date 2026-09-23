// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Rate is how much of one severity's work met its deadline.
//
// Three numbers rather than two, and the third is the whole point. A rate that
// counts an approved deferral as a failure punishes the deliberate act the
// deferral mechanism exists to make possible, and within a quarter people stop
// deferring and start letting things run late silently. So a deferral is its
// own column: not a success, not a failure, and visible.
type Rate struct {
	Severity string
	// Closed is how many closed with a deadline to be judged against, Met how
	// many closed before it, and Late how many did not.
	Closed int
	Met    int
	Late   int
	// Deferred is how many of the ones still open carry a standing deferral,
	// which is somebody having moved the date deliberately rather than having
	// missed it.
	Deferred int
	// Overdue is how many are still open, past their deadline, with no
	// deferral standing — plainly late, which is the number the rate is
	// usually being asked about.
	Overdue int
	// Open is what Deferred and Overdue are a share of. Without it the two
	// were numerators with no denominator, so "eleven overdue" could not be
	// read as a proportion of anything — which is what a rate is.
	Open int
}

// Compliance is what proportion of the work met its deadline, by severity.
//
// Arithmetic rather than storage. A closed row keeps the deadline it
// carried, and only *open* rows lose one at end-of-life or below the line — so
// everything this needs is already there, and nothing is precomputed.
// The period bounds what closed in it; what is open is always now. A rate
// asked for last year says how much of the work finished then met its date.
// The open half is a statement about the present whatever period was asked
// for, because reconstructing what stood open on a date gone by is the
// reconstruction the register refuses — deadlines are recomputed when the
// policy moves and dropped below the line and past end of life, so a deadline
// "as of" a past date is not recoverable.
func (s *Store) Compliance(ctx context.Context, subject access.Subject,
	scope Scope, since, until time.Time) ([]Rate, error) {

	// A product is required, for the reason every list here requires one: a
	// place identity carries no product, so a decision correlated without one
	// would reach decisions made in every product in the deployment.
	productID, visible, targets, err := s.inScope(ctx, subject, scope, &Filter{})
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, nil
	}

	now := s.now().UTC()
	var rows []struct {
		Severity string `bun:"band"`
		Closed   int    `bun:"closed"`
		Met      int    `bun:"met"`
		Deferred int    `bun:"deferred"`
		Overdue  int    `bun:"overdue"`
		Open     int    `bun:"still_open"`
	}
	// The period, as the two halves of a condition on when a row closed. An
	// unbounded side is left out rather than bound to a moment that stands
	// for forever, so a rate asked for nothing in particular is the rate over
	// everything held.
	within, bounds := "", []any{}
	if !since.IsZero() {
		within, bounds = ` AND f.closed_at >= ?`, append(bounds, since)
	}
	if !until.IsZero() {
		within, bounds = within+` AND f.closed_at < ?`, append(bounds, until)
	}
	// A standing deferral at the place, asked as a correlated existence test
	// rather than a join, so a place with two of them counts once.
	//
	// Correlated by product as well as by place, because a place identity
	// carries none — without it a deferral made in another product that ships
	// the same component would answer here.
	standing, held := InForce()
	deferred := `EXISTS (SELECT 1 FROM "decision" AS "de"
		JOIN "claim" AS "cl" ON cl.id = de.claim_id
		WHERE de.product_id = ?
		  AND de.vulnerability_id = f.vulnerability_id
		  AND de.place_identity = f.place_identity
		  AND de.live_key IS NOT NULL
		  AND ` + standing + `
		  AND cl.outcome = 'deferred')`
	// The product, then whatever the standing test binds, in that order.
	covers := append([]any{productID}, held...)
	// Grouped to the unit every other screen counts in — one issue at one
	// component — rather than to the row. Counted per row, a kernel flaw at
	// forty-five places was forty-five late things and one late thing on the
	// findings list beside it, and the two numbers carry the same name. The
	// rate is a claim about how much work met its deadline, and the unit of
	// work is what somebody decides about.
	group := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.Here, productID).
		ColumnExpr(rating.BandExpr+` AS "band"`).
		ColumnExpr("SUM(CASE WHEN f.closed_at IS NOT NULL AND f.due_at IS NOT NULL "+
			within+` THEN 1 ELSE 0 END) AS "judged"`, bounds...).
		ColumnExpr("SUM(CASE WHEN f.closed_at IS NOT NULL AND f.due_at IS NOT NULL "+
			within+` AND f.closed_at > f.due_at THEN 1 ELSE 0 END) AS "late"`, bounds...).
		ColumnExpr(`SUM(CASE WHEN f.closed_at IS NULL THEN 1 ELSE 0 END) AS "still_open"`).
		ColumnExpr("SUM(CASE WHEN f.closed_at IS NULL AND "+deferred+
			` THEN 1 ELSE 0 END) AS "covered"`, covers...).
		ColumnExpr("SUM(CASE WHEN f.closed_at IS NULL AND f.due_at IS NOT NULL "+
			"AND f.due_at < ? AND NOT "+deferred+` THEN 1 ELSE 0 END) AS "past_due"`,
			append([]any{now}, covers...)...).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr(rating.BandExpr + ", f.vulnerability_id, f.component_id")

	// Each of the four, read about a group rather than about a row.
	// Closed when no place is still open and at least one of them carried a
	// deadline to be judged against; met when none of those was late;
	// deferred when every open place is covered by one, because a deferral
	// over some of a group leaves the rest running; overdue when anything
	// open is past its date and not covered.
	err = s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, group).
		ColumnExpr(`grouped.band AS "band"`).
		ColumnExpr("SUM(CASE WHEN grouped.still_open = 0 AND grouped.judged > 0 "+
			`THEN 1 ELSE 0 END) AS "closed"`).
		ColumnExpr("SUM(CASE WHEN grouped.still_open = 0 AND grouped.judged > 0 "+
			`AND grouped.late = 0 THEN 1 ELSE 0 END) AS "met"`).
		ColumnExpr("SUM(CASE WHEN grouped.still_open > 0 "+
			`AND grouped.covered = grouped.still_open THEN 1 ELSE 0 END) AS "deferred"`).
		ColumnExpr(`SUM(CASE WHEN grouped.past_due > 0 THEN 1 ELSE 0 END) AS "overdue"`).
		ColumnExpr(`SUM(CASE WHEN grouped.still_open > 0 THEN 1 ELSE 0 END) AS "still_open"`).
		GroupExpr("grouped.band").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read how much met its deadline: %w", err)
	}

	// In the order the words rank, worst first, and every band present even
	// where it is empty: a rate table with rows missing reads as a rate table
	// that has been narrowed.
	by := map[string]Rate{}
	for _, row := range rows {
		by[row.Severity] = Rate{
			Severity: row.Severity, Closed: row.Closed, Met: row.Met,
			Late: row.Closed - row.Met, Deferred: row.Deferred, Overdue: row.Overdue,
			Open: row.Open,
		}
	}
	out := make([]Rate, 0, len(ranked))
	for i := len(ranked) - 1; i >= 0; i-- {
		word := ranked[i]
		one, held := by[word]
		if !held {
			one = Rate{Severity: word}
		}
		out = append(out, one)
	}
	return out, nil
}

// Since is a moment a filter compares against, or none where nothing was
// asked. Here rather than in the interface so that "a date" means one thing.
func Since(at string) (*time.Time, error) {
	if at == "" {
		return nil, nil
	}
	when, err := time.Parse(time.DateOnly, at)
	if err != nil {
		return nil, fmt.Errorf("%q is not a date, written as 2026-03-31", at)
	}
	return &when, nil
}
