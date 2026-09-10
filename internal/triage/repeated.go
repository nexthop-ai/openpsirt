package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Repeated is one place that keeps being put off.
//
// A cumulative threshold already refuses a *further* deferral past a point,
// which acts on one item at a time. What that cannot show is the shape across
// everything: one item deferred three times is a judgment, and forty of them
// is a policy nobody wrote down and nobody agreed to.
type Repeated struct {
	Product       string `bun:"product"`
	Vulnerability string `bun:"vulnerability"`
	Severity      string `bun:"severity"`
	// PlaceIdentity names the place rather than describing it. What it is
	// called depends on the build being looked at, and this list is not about
	// one build.
	PlaceIdentity string `bun:"place_identity"`
	// Times is how often it has been put off, and Total is how long it has
	// been put off for, added up. The two answer different questions: three
	// short deferrals and one long one are different situations, and a list
	// carrying only one of the numbers hides whichever it is not.
	Times int `bun:"times"`
	// TotalDays is the sum of every deferral's span, in days.
	//
	// **A fraction, not a whole number.** Adding two moments' difference gives
	// a fractional day on all four engines, and declaring it as an integer
	// scanned on none of them: one refused a float outright and three handed
	// back a decimal string. Rounded where it is shown rather than where it is
	// read, so nothing rounds twice.
	TotalDays float64 `bun:"total_days"`
	// Standing says a deferral is in force now rather than all of them having
	// run out. Something put off three times and now decided is history; the
	// same thing still being put off is the pattern this list is for.
	Standing bool `bun:"standing"`
	// LastUntil is the furthest any of them reached.
	LastUntil time.Time `bun:"last_until"`
}

// DefaultRepeatedAt is how many deferrals make something worth listing.
//
// Two, because one is an ordinary judgment and the list exists for the pattern
// rather than for the act. It is a starting point rather than a rule: how many
// is too many is a judgment about a product, and the caller may ask for more.
const DefaultRepeatedAt = 2

// Repeats lists places that have been deferred more than once, worst first.
//
// **Counted over the decisions rather than over the findings.** A deferral is
// one judgment about a place; the places fan out into as many findings as the
// component has consumers, and counting those would order the list by how far
// a component spreads through an image.
func (s *Store) Repeats(ctx context.Context, subject access.Subject, productID int64,
	atLeast, limit int) ([]Repeated, error) {

	if subject.Kind != access.Person {
		return nil, nil
	}
	if atLeast <= 0 {
		atLeast = DefaultRepeatedAt
	}
	limit = database.InBulk.Of(limit)

	var rows []Repeated
	q := s.db.NewSelect().
		TableExpr(`"decision" AS de`).
		Join(`JOIN "vulnerability" AS v ON v.id = de.vulnerability_id`).
		Join(`JOIN "product" AS p ON p.id = de.product_id`).
		// The argument, which is where the outcome and the date live.
		Join(`JOIN "claim" AS cl ON cl.id = de.claim_id`).
		ColumnExpr("p.display_name AS product").
		ColumnExpr("v.identifier AS vulnerability").
		ColumnExpr("COALESCE(v.assessed_severity, v.severity, '') AS severity").
		ColumnExpr("de.place_identity AS place_identity").
		ColumnExpr("COUNT(*) AS times").
		ColumnExpr("MAX(cl.deferred_until) AS last_until").
		// Summed in days here rather than as intervals, because the four
		// engines return an interval as four different things and a caller
		// would have to know which one it was talking to.
		ColumnExpr(deferredDays(s.db)+" AS total_days").
		ColumnExpr("MAX(CASE WHEN de.live_key IS NOT NULL AND cl.deferred_until > ?"+
			" THEN 1 ELSE 0 END) AS standing", s.now().UTC()).
		Where("cl.outcome = ?", Deferred).
		// What was taken back was never time anything spent put off.
		Where("de.state <> ?", Withdrawn).
		Where("cl.deferred_until IS NOT NULL").
		GroupExpr("p.display_name, v.identifier, v.assessed_severity, v.severity, de.place_identity").
		Having("COUNT(*) >= ?", atLeast).
		// The most put-off first, and then the longest: a list read from the
		// top should start with the thing somebody has avoided most.
		OrderExpr("times DESC, total_days DESC, vulnerability").
		Limit(limit)

	if productID > 0 {
		q = q.Where("de.product_id = ?", productID)
	}
	q = readableBy(q, subject, "de")
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what keeps being put off: %w", err)
	}
	return rows, nil
}

// deferredDays sums how long each deferral ran for, in whole days, through the
// one place an engine is asked how to subtract two moments.
func deferredDays(db bun.IDB) string {
	return "COALESCE(SUM(" + database.SecondsBetween(db,
		"de.proposed_at", "cl.deferred_until") + ") / 86400, 0)"
}
