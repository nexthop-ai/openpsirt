package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Spent is what the work went into, for one component in one product.
//
// **Where the effort went, not how much there is.** Every other figure here
// counts the backlog — what is open, what is overdue, how long things wait.
// None of them answers the question a manager asks at a planning meeting:
// what did the last quarter actually go into. Read from the record, because
// the record is where the acts are: a claim argued is a piece of work
// somebody did, whatever it concluded.
type Spent struct {
	Product   string `bun:"product"`
	Component string `bun:"component"`
	// Claims is how many arguments were made — the unit a person works in,
	// one act however many rows it wrote — and Decisions how many places
	// those reached. The pair is the point: ten claims over ten places and
	// one claim over a thousand are different afternoons.
	Claims    int `bun:"claims"`
	Decisions int `bun:"decisions"`
	// People is how many different people argued about it. One person's
	// component and a whole team's are different situations, and a list
	// carrying only the volume hides which it is.
	People int `bun:"people"`
	// Promised, Dismissed and Deferred are what came out of those claims,
	// counted as claims for the same reason: what a component's time went
	// into is as much the shape of the answers as the volume of them. Forty
	// arguments that produced forty dismissals and forty that produced forty
	// upgrades are different quarters.
	Promised  int `bun:"promised"`
	Dismissed int `bun:"dismissed"`
	Deferred  int `bun:"deferred"`
}

// Effort is what the work went into over a period, worst first.
//
// Counted over the claims rather than over the rows they wrote, for the
// reason the review queue is: a claim is one person's act, and counting its
// rows measures how far a component fans out through an image rather than
// anybody's afternoon.
func (s *Store) Effort(ctx context.Context, subject access.Subject, only Measuring,
	since, until time.Time, limit int) ([]Spent, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are different
	// statements, and this is the second.
	if subject.Kind != access.Person {
		return nil, access.Denied("read where the work went")
	}
	if until.IsZero() {
		until = s.now().UTC()
	}
	if since.IsZero() {
		since = until.AddDate(0, 0, -90)
	}
	limit = database.AList.Of(limit)

	// What a judgment was about, reached through a finding at the place — the
	// same way the record's own component filter reaches it. A judgment about
	// something since removed still names it, which is what a report about
	// where the time went has to keep.
	named := `(SELECT MIN(cc.name) FROM "finding" AS "cf"
		JOIN "component" AS "cc" ON cc.id = cf.component_id
		WHERE cf.vulnerability_id = de.vulnerability_id
		  AND cf.place_identity = de.place_identity)`

	var rows []Spent
	q := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "product" AS "p" ON p.id = de.product_id`).
		// The argument, which is where an outcome lives.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`MIN(p.display_name) AS "product"`).
		ColumnExpr(named+` AS "component"`).
		ColumnExpr(`COUNT(DISTINCT de.claim_id) AS "claims"`).
		ColumnExpr(`COUNT(*) AS "decisions"`).
		ColumnExpr(`COUNT(DISTINCT de.proposed_by) AS "people"`).
		// What came out of them, each counted as claims: the outcome is the
		// claim's, and counting its rows would weigh a judgment by how far
		// its component happens to fan out.
		ColumnExpr(`COUNT(DISTINCT CASE WHEN cl.outcome IN (?) THEN de.claim_id END)`+
			` AS "promised"`, bun.List([]Outcome{UpgradeNeeded, PatchNeeded})).
		ColumnExpr(`COUNT(DISTINCT CASE WHEN cl.outcome IN (?) THEN de.claim_id END)`+
			` AS "dismissed"`, bun.List([]Outcome{NotApplicable, WontFix, AlreadyFixed})).
		ColumnExpr(`COUNT(DISTINCT CASE WHEN cl.outcome = ? THEN de.claim_id END)`+
			` AS "deferred"`, Deferred).
		Where("de.proposed_at >= ?", since).
		Where("de.proposed_at < ?", until).
		GroupExpr("de.product_id, " + named).
		OrderExpr("claims DESC, decisions DESC, component").
		Limit(limit)
	q = only.narrow(readableBy(q, subject, "de"))
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read where the work went: %w", err)
	}
	return rows, nil
}
