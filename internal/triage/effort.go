// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Spent is what the work went into, for one component in one product.
//
// The destination of the effort, not the amount of it. Every other figure here
// counts the backlog — what is open, what is overdue, how long things wait.
// None of them answers the question a manager asks at a planning meeting:
// what did the last quarter actually go into. Read from the record, because
// the record is where the acts are: a claim argued is a piece of work
// somebody did, whatever it concluded.
type Spent struct {
	Product     string `bun:"product"`
	ProductName string `bun:"product_name"`
	Component   string `bun:"component"`
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
	// Total is how many rows the question has before the limit, carried on
	// every row by the statement that reads the page.
	Total int `bun:"total"`
}

// Effort is what the work went into over a period, worst first.
//
// Counted over the claims rather than over the rows they wrote, for the
// reason the review queue is: a claim is one person's act, and counting its
// rows measures how far a component fans out through an image rather than
// anybody's afternoon.
func (s *Store) Effort(ctx context.Context, subject access.Subject, only Measuring,
	since, until time.Time, limit, offset int) ([]Spent, int, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are different
	// statements, and this is the second.
	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read where the work went")
	}
	if until.IsZero() {
		until = s.now().UTC()
	}
	// An absent start is the beginning, which is what a period's zero side
	// means: a default substituted here is a figure over a window nobody
	// asked for, under a response saying the period ran from the beginning.
	limit = database.AList.Of(limit)

	// The joins, the narrowing and the grouping on their own, so the page and
	// the count ask the same question.
	grouped := func() *bun.SelectQuery {
		q := s.db.NewSelect().
			TableExpr(finding.Decisions).
			Join(`JOIN "product" AS "p" ON p.id = de.product_id`).
			// The argument, which is where an outcome lives.
			Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
			// The judgment's subject, reached through the findings at the
			// place — the same correlation the record's own component filter
			// makes. A judgment about something since removed matches nothing and
			// keeps its row, which is what a report about where the time went has
			// to keep.
			//
			// Joined rather than asked as a subquery in the select list. The
			// same expression in the list and in the grouping is refused outright
			// by MySQL and MariaDB under ONLY_FULL_GROUP_BY, because it reads
			// columns the grouping does not carry — so the report answered on two
			// engines and was a 500 on the other two.
			//
			// A place sits in as many builds as hold it, so this multiplies the
			// rows. Every figure below counts distinct identifiers for that
			// reason: what is being counted is acts, and an act is one row of the
			// decision table however many builds share the place it names.
			Join(`LEFT JOIN "finding" AS "pf" ON pf.vulnerability_id = dv.issue_id
			AND pf.place_identity = de.place_identity`).
			Join(`LEFT JOIN "component" AS "pc" ON pc.id = pf.component_id`).
			Where("de.proposed_at < ?", until).
			GroupExpr(`de.product_id, COALESCE(pc.name, '')`)
		return only.narrow(readableBy(from(q, "de.proposed_at", since), subject, "de"))
	}

	var rows []Spent
	q := grouped().
		ColumnExpr(`MIN(p.name) AS "product"`).
		ColumnExpr(`MIN(`+catalog.ShownExpr("p")+`) AS "product_name"`).
		ColumnExpr(`COALESCE(pc.name, '') AS "component"`).
		ColumnExpr(`COUNT(DISTINCT de.claim_id) AS "claims"`).
		ColumnExpr(`COUNT(DISTINCT de.id) AS "decisions"`).
		ColumnExpr(`COUNT(DISTINCT de.proposed_by) AS "people"`).
		// The upgrades that came out of them, each counted as claims: the
		// outcome is the claim's, and counting its rows would weigh a judgment
		// by how far its component happens to fan out.
		ColumnExpr(`COUNT(DISTINCT CASE WHEN cl.outcome IN (?) THEN de.claim_id END)`+
			` AS "promised"`, bun.List([]Outcome{UpgradeNeeded, PatchNeeded})).
		ColumnExpr(`COUNT(DISTINCT CASE WHEN cl.outcome IN (?) THEN de.claim_id END)`+
			` AS "dismissed"`, bun.List(OutcomesDismissing())).
		ColumnExpr(`COUNT(DISTINCT CASE WHEN cl.outcome = ? THEN de.claim_id END)`+
			` AS "deferred"`, Deferred).
		// How many rows the question has, counted over the grouped result
		// and before the limit. A total taken off the page reads a list cut
		// at the limit as complete.
		ColumnExpr(`COUNT(*) OVER () AS "total"`).
		// Ended on the group's own key, so the order is total: one component
		// in two products with equal counts ties on everything before it, and
		// an order that ties lets an engine's top-N sort repeat one row and
		// skip the other across pages.
		OrderExpr("claims DESC, decisions DESC, component, de.product_id").
		Limit(limit).Offset(offset)
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read where the work went: %w", err)
	}
	if len(rows) > 0 {
		return rows, rows[0].Total, nil
	}
	if offset == 0 {
		return rows, 0, nil
	}
	// A page past the end carries no row to read the count off.
	total, err := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, grouped().ColumnExpr("de.product_id")).
		Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count where the work went: %w", err)
	}
	return rows, total, nil
}
