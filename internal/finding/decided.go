// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strings"

	"github.com/uptrace/bun"
)

// The decision state of a group, counted per place.
//
// Four counts over our decisions in one product, at each place and at the
// versions that place holds now. A place with two decisions is one place, and
// the number of places is exactly what the state words compare against, so a
// count never joins the decisions straight into the rows it counts.
//
// Two shapes ask it, and the conditions are the same in both:
//
//   - decidedAs, a correlated EXISTS per place, for a page of groups, which
//     reads a few hundred places.
//   - decisionsAtPlaces, one row per decided place built once from the decision
//     side and joined on the finding, for a count over every open place in a
//     product. The match from a decision to its places is decisionsOutward,
//     which the state filter's table is built on too.
//
// The EXISTS runs once per place it is asked of, which is nothing on a page and
// 367,000 probes for a product's totals: 2.1 s a statement on PostgreSQL,
// against 0.2 s for the joined table, which starts from the decisions rather
// than from the findings.
//
// Written once, because spelled again at every site the conditions drift: a
// row requiring a live key for "waiting" where the filter does not puts a
// claim proposed and then withdrawn in the filter's waiting bucket, with no
// state word on the row that comes back.

// decisionState is one of those counts: the column it lands in, the condition
// that recognizes it, and the words that condition binds.
//
// Carried together so a caller cannot take the fragment and leave the value
// behind, which is the same reason Filter.product answers with both.
type decisionState struct {
	alias     string
	condition string
	args      []any
}

// The four states a row is counted in. Lapsed is counted whether or not the
// claim still stands, because a lapse is what happened to it; the other three
// require the live key, because a claim that no longer stands is not waiting,
// is not agreed, and is not with its author.
//
// Waiting is a proposal that needs a second person. A proposal that needs
// nobody is in force, and counts with the agreed ones.
var (
	claimWaiting = decisionState{"waiting_here",
		" AND de.state = ? AND de.needs_approval = ? AND de.live_key IS NOT NULL",
		[]any{"proposed", true}}
	claimApproved = func() decisionState {
		inForce, args := InForce()
		return decisionState{"approved_here", " AND " + inForce + " AND de.live_key IS NOT NULL", args}
	}()
	claimLapsed = decisionState{"lapsed_here",
		" AND de.state = ?", []any{"lapsed"}}
	claimSentBack = decisionState{"sent_back_here",
		" AND de.state = ? AND de.live_key IS NOT NULL AND de.sent_back_at IS NOT NULL",
		[]any{"proposed"}}
)

// decisionCounts appends one column per state to q.
//
// The product is the only thing that differs between callers — a bound number
// inside one product, and the row's own column across them — so it arrives the
// way Filter.product answers it, as a fragment with the arguments it needs.
func decisionCounts(q *bun.SelectQuery, product string, args []any, states ...decisionState) *bun.SelectQuery {
	for _, state := range states {
		bound := append(append([]any{}, args...), state.args...)
		q = q.ColumnExpr(decidedAs(product, state), bound...)
	}
	return q
}

// standsAs is the same question asked of one place rather than counted over a
// group: does a decision in this state cover this finding.
//
// The row's count and the filter that selects on it have to be the same
// question, and the sent-back filter had written its own — without the
// product and without the version match — so it matched a claim sent back in
// another product, or one keyed on a version the place no longer holds, and
// returned groups whose own sent-back count was zero.
func standsAs(product string, state decisionState) string {
	// The finding is joined again inside rather than read from the outer
	// query, because the versions the match is keyed on hang off the
	// component and the consumer, and the statements this narrows have joined
	// neither. Every join here is the subquery's own and the only thing read
	// from outside it is the row's identifier, which is the shape the state
	// filter's derived table already uses on all four engines.
	return `EXISTS (SELECT 1 FROM "finding" AS "f2"
			JOIN "component" AS "c" ON c.id = f2.component_id
			LEFT JOIN "component" AS "uc" ON uc.id = f2.consumer_id
			JOIN "vulnerability" AS "dv" ON dv.issue_id = f2.vulnerability_id
			JOIN "decision" AS "de" ON de.vulnerability_id = dv.id
			  AND de.place_identity = f2.place_identity
			JOIN "claim" AS "cl" ON cl.id = de.claim_id
			WHERE f2.id = f.id
			  AND de.product_id = ` + product + `
			  AND ` + coversHere + state.condition + `)`
}

// decidedAs is the one spelling of the count, for the states above and for
// the one question HowItStands asks that none of them covers.
//
// The alias is quoted here rather than carried already quoted, because a name
// assembled from two literals is the one shape the gate over invented names
// cannot see — it reads string literals, and there is no literal holding this
// name. Quoting it at the joint is what puts it back inside a rule something
// checks.
func decidedAs(product string, state decisionState) string {
	return `SUM(CASE WHEN EXISTS (SELECT 1 FROM ` + Decisions + `
			JOIN "claim" AS "cl" ON cl.id = de.claim_id
			WHERE ` + DecisionAt(product) + `
			  AND ` + coversHere + state.condition + `) THEN 1 ELSE 0 END) AS "` + state.alias + `"`
}

// decisionsAtPlaces is one row per open finding in a product that a decision of
// ours there covers, with a column per state saying whether one of the
// decisions covering it is in that state. Joined to a query over finding AS f
// as `LEFT JOIN (?) AS "dd" ON dd.finding_id = f.id` and read through
// placesDecided.
//
// Built on decisionsOutward, the table the state filter is built on. The
// findings it reaches are not held to the product's builds: the decision is,
// and the join on the finding's identifier drops a place in another product
// that shares the issue and the place identity. Holding them as well was
// measured slower, 1.5 s against 1.1 s with 133,000 decisions on PostgreSQL.
func decisionsAtPlaces(q *bun.SelectQuery, productID int64, states ...decisionState) *bun.SelectQuery {
	decided := decisionsOutward(q)
	for _, state := range states {
		decided = decided.ColumnExpr(`MAX(CASE WHEN `+strings.TrimPrefix(state.condition, " AND ")+
			` THEN 1 ELSE 0 END) AS "`+state.alias+`"`, state.args...)
	}
	return decided.Where("de.product_id = ?", productID)
}

// decisionsOutward is every open finding a decision covers, one row per
// finding, reached from the decision side: the decision is matched to a place
// by its issue and place identity, held to the versions the place holds now,
// and joined to its claim. Callers add a column per thing they ask of the
// decisions and say which product a decision has to belong to.
//
// The one spelling of how a decision reaches the places it covers, shared by
// the overview's counts and the state filter, so a change to the match is made
// once and reaches both.
//
// The decision is outermost through CROSS JOIN ... WHERE. It is an inner join
// on every engine, and on SQLite it also fixes the order: left to choose,
// SQLite starts from every open finding and reads every decision of its
// product once per row.
func decisionsOutward(q *bun.SelectQuery) *bun.SelectQuery {
	return decisionsOver(q, `"finding" AS "f2"`).
		ColumnExpr(`f2.id AS "finding_id"`).
		Where("f2.closed_at IS NULL").
		GroupExpr("f2.id")
}

// decisionsOver is every decision reaching a place read from source as "f2",
// one row per decision and place: the finding table itself, or a population of
// places that already carries its own conditions, with the identifier, the
// issue, the place identity, the component and the consumer under their own
// names. The caller groups it.
func decisionsOver(q *bun.SelectQuery, source string, args ...any) *bun.SelectQuery {
	return q.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(DecisionIssue).
		Join(`CROSS JOIN `+source, args...).
		Where("f2.vulnerability_id = dv.issue_id AND f2.place_identity = de.place_identity").
		// The component and the consumer, for the versions: a live claim is
		// about the place at the versions it was keyed on.
		Join(`JOIN "component" AS "c" ON c.id = f2.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f2.consumer_id`).
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Where(coversHere)
}

// placesDecided is how many of a group's places decisionsAtPlaces marks in one
// state, under the state's own alias. A place no decision covers has no row
// in the joined table and counts as none.
func placesDecided(state decisionState) string {
	return `SUM(COALESCE(dd.` + state.alias + `, 0)) AS "` + state.alias + `"`
}
