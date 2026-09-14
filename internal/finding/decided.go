package finding

import "github.com/uptrace/bun"

// How far a group has been decided, counted per place.
//
// Four correlated counts over our decisions in one product, at each place and
// at the versions that place holds now. Asked as an EXISTS per place rather
// than by joining the decisions in, because a join multiplies the rows — a
// place with two decisions counts twice — and the number of places is exactly
// what the state words compare against.
//
// Written once because it was written four times, with each of the conditions
// spelled again at every site. They had already drifted: the row required a
// live key for "waiting" where the filter did not, so a claim proposed and
// then withdrawn sat in the filter's waiting bucket and drew no state word on
// the row that came back. The filter's own counts keep a different *shape* on
// purpose — a joined derived table rather than a correlated subquery, because
// asking per row was 241,479 probes to say "nothing has been decided here" —
// and it is the conditions that have to agree, not the shape.

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
var (
	claimWaiting = decisionState{"waiting_here",
		" AND de.state = ? AND de.live_key IS NOT NULL", []any{"proposed"}}
	claimApproved = decisionState{"approved_here",
		" AND de.state = ? AND de.live_key IS NOT NULL", []any{"approved"}}
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
			JOIN "decision" AS "de" ON de.vulnerability_id = f2.vulnerability_id
			  AND de.place_identity = f2.place_identity
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
	return `SUM(CASE WHEN EXISTS (SELECT 1 FROM "decision" AS "de"
			WHERE de.product_id = ` + product + `
			  AND de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND ` + coversHere + state.condition + `) THEN 1 ELSE 0 END) AS "` + state.alias + `"`
}
