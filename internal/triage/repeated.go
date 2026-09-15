package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
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
	atLeast, limit int) ([]Repeated, int, error) {

	return s.RepeatsPage(ctx, subject, productID, atLeast, limit, 0)
}

// RepeatsPage is the same list, from a position in it, with how many there are
// in all.
//
// Paged because a ceiling with no offset means what is past it cannot be read
// through the API at all — and this one grows with the estate, which is the
// whole subject of the report.
func (s *Store) RepeatsPage(ctx context.Context, subject access.Subject, productID int64,
	atLeast, limit, offset int) ([]Repeated, int, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second.
	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read which deferrals repeat")
	}
	if atLeast <= 0 {
		atLeast = DefaultRepeatedAt
	}
	limit = database.InBulk.Of(limit)

	var rows []Repeated
	q := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = de.vulnerability_id`).
		Join(`JOIN "product" AS "p" ON p.id = de.product_id`).
		// And what that product rates the issue, where it rates it anything.
		// The report is per product already, and a rating belongs to one — so
		// the word beside a repeated deferral is the word the team doing the
		// deferring holds.
		Join(finding.RatedFor(finding.RatedOnDecision)).
		// The argument, which is where the outcome and the date live.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		// Grouped on the product's identifier and the issue's, with the names
		// carried along as labels. Grouping on the display name merged two
		// products a catalog is free to display alike — one ordinary judgment
		// apiece became a repeated-deferral pattern with a total summed across
		// both, and a genuine per-product pattern was reported against
		// whichever name the group collapsed onto. Only the product's name is
		// unique, and it is not the one anybody reads.
		ColumnExpr(`MIN(p.display_name) AS "product"`).
		ColumnExpr(`MIN(v.identifier) AS "vulnerability"`).
		ColumnExpr("MIN("+finding.EffectiveSeverityExpr+`) AS "severity"`).
		ColumnExpr(`de.place_identity AS "place_identity"`).
		// Counted over the deferrals that actually held. One taken back
		// before it took effect put nothing off, and counting it would make
		// correcting a mistake read as avoiding the work.
		ColumnExpr("SUM(CASE WHEN "+heldSeconds(s.db)+` > 0 THEN 1 ELSE 0 END) AS "times"`).
		ColumnExpr(`MAX(cl.deferred_until) AS "last_until"`).
		// Summed in days here rather than as intervals, because the four
		// engines return an interval as four different things and a caller
		// would have to know which one it was talking to.
		ColumnExpr(deferredDays(s.db)+` AS "total_days"`).
		ColumnExpr("MAX(CASE WHEN de.live_key IS NOT NULL AND cl.deferred_until > ?"+
			` THEN 1 ELSE 0 END) AS "standing"`, s.now().UTC()).
		Where("cl.outcome = ?", Deferred).
		// Withdrawn ones counted for the span they were in force, the way the
		// threshold counts them. Left out, the report built to catch
		// withdraw-and-defer-again was blind to exactly that pattern.
		Where("cl.deferred_until IS NOT NULL").
		GroupExpr("de.product_id, de.vulnerability_id, de.place_identity").
		Having("SUM(CASE WHEN "+heldSeconds(s.db)+" > 0 THEN 1 ELSE 0 END) >= ?", atLeast).
		// The most put-off first, and then the longest: a list read from the
		// top should start with the thing somebody has avoided most.
		OrderExpr("times DESC, total_days DESC, vulnerability")

	if productID > 0 {
		q = q.Where("de.product_id = ?", productID)
	}
	q = readableBy(q, subject, "de")
	// Counted over the grouping, which is a place rather than a deferral:
	// the report's own subject is how many places keep being put off.
	total, err := s.db.NewSelect().TableExpr(`(?) AS "repeating"`, q).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what keeps being put off: %w", err)
	}
	if err := q.Limit(limit).Offset(offset).Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read what keeps being put off: %w", err)
	}
	return rows, total, nil
}

// deferredDays sums how long each deferral ran for, in whole days, through the
// one place an engine is asked how to subtract two moments.
func deferredDays(db bun.IDB) string {
	return "COALESCE(SUM(" + heldSeconds(db) + ") / 86400, 0)"
}

// heldSeconds is how long one deferral put its place off for, in seconds.
//
// The SQL half of the rule the threshold applies in Go: from when it was
// asked for to the date it returns on, cut short where it was taken back
// before that date, and never negative. Written as a CASE rather than with a
// two-argument minimum, because the four engines spell that three ways.
func heldSeconds(db bun.IDB) string {
	ends := database.Composed(`(CASE WHEN de.state = '` + string(Withdrawn) + `'
			AND de.ended_at IS NOT NULL AND de.ended_at < cl.deferred_until
		THEN de.ended_at ELSE cl.deferred_until END)`)
	seconds := database.SecondsBetween(db, database.Column(db, "de.proposed_at"), ends)
	return "(CASE WHEN " + seconds + " > 0 THEN " + seconds + " ELSE 0 END)"
}
