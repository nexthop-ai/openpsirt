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
}

// Compliance is what proportion of the work met its deadline, by severity.
//
// **Arithmetic rather than storage.** A closed row keeps the deadline it
// carried, and only *open* rows lose one at end-of-life or below the line — so
// everything this needs is already there, and nothing is precomputed.
func (s *Store) Compliance(ctx context.Context, subject access.Subject,
	scope Scope) ([]Rate, error) {

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
			`THEN 1 ELSE 0 END) AS "judged"`).
		ColumnExpr("SUM(CASE WHEN f.closed_at IS NOT NULL AND f.due_at IS NOT NULL "+
			`AND f.closed_at > f.due_at THEN 1 ELSE 0 END) AS "late"`).
		ColumnExpr(`SUM(CASE WHEN f.closed_at IS NULL THEN 1 ELSE 0 END) AS "still_open"`).
		ColumnExpr("SUM(CASE WHEN f.closed_at IS NULL AND "+deferred+
			` THEN 1 ELSE 0 END) AS "covered"`, covers...).
		ColumnExpr("SUM(CASE WHEN f.closed_at IS NULL AND f.due_at IS NOT NULL "+
			"AND f.due_at < ? AND NOT "+deferred+` THEN 1 ELSE 0 END) AS "past_due"`,
			append([]any{now}, covers...)...).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr(rating.BandExpr + ", f.vulnerability_id, f.component_id")

	// What each of the four means about a group rather than about a row.
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
