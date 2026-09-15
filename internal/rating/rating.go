// Package rating is how a product's own rating of an issue is read in SQL.
//
// A leaf, and deliberately a small one. What a finding's severity *is* has one
// rule — the product's word where it has stated one, the published word
// otherwise — and the two packages that have to apply it cannot both own it:
// internal/finding imports internal/graph to walk a subtree, so internal/graph
// cannot import internal/finding to ask what a band is. The band strip on the
// component tree was drawn from the published rating alone for exactly that
// reason, and a product that re-rated an issue saw its own decision in five
// screens and the world's in four others.
//
// So the join and the two expressions live here, where neither side owns them
// and both may say them. The rating *row* does not: it is written and read
// through internal/finding, which is where a rating is proposed, agreed and
// put in force. What moved is only the spelling a query needs.
package rating

// On is where a query finds the product it is asking about.
//
// The spellings are named rather than passed as text. A placeholder cannot
// bind a column name, so the product half of this join is spliced in — and a
// function taking a string would leave nothing between it and a column name
// arriving from a query parameter except that today's callers all pass a
// literal. Naming them is what makes that structural rather than a habit
// (REQ-66).
type On string

const (
	// OnStream is the product the row's stream belongs to, for a query that
	// spans products and reads each row's own.
	OnStream On = "st.product_id"
	// OnDecision is the product a decision was recorded in.
	OnDecision On = "de.product_id"
	// onBound is one product, bound. Used through Here.
	onBound On = "?"
)

// For is the left join that brings a product's own rating into a query that
// already joins vulnerability AS v.
//
// Left, because most issues are rated by nobody and those are the rows every
// list is mostly made of.
//
// Every caller already joined the vulnerability, because that is where the
// rating used to be. So this swaps a column for a join rather than adding one
// where none existed.
func For(product On) string {
	return `LEFT JOIN "issue_rating" AS "ir" ON ir.vulnerability_id = v.id` +
		` AND ir.product_id = ` + string(product)
}

// Here is For with the product bound.
//
// The same join rather than a second spelling of it: written out twice, a
// change to one is a change the other quietly does not make.
var Here = For(onBound)

// BandExpr is the rating a finding is judged by, folded to one of the four
// words that rank.
//
// Spelled once, and used by both the line and the deadline, because they were
// briefly two rules reading the same fact and they disagreed: the deadline
// treats an unrated issue as a medium, on the grounds that unknown is not
// harmless, while the line was treating it as below everything. On a real
// image that was **91,040 findings rated "unknown"** dropping out of the
// working list *and* off any clock, which is the opposite of what an unknown
// rating should cause. Every bug in this project's identity and expiry rules
// came from letting one fact into two rules; this is that lesson arriving in a
// third place. This product's where it has stated one, the published one
// otherwise: being able to say a published rating is wrong is pointless if
// everything that ranks and filters then ignores us.
//
// Read off the rating joined by For, so a query using this joins that too and
// says which product it is asking about. A statement that reads the expression
// without the join does not compile on any of the four engines, which is the
// failure being chosen — the alternative is a query that silently answers for
// the wrong product.
const BandExpr = `CASE
	WHEN COALESCE(ir.severity, v.severity, '') = 'critical' THEN 'critical'
	WHEN COALESCE(ir.severity, v.severity, '') = 'high' THEN 'high'
	WHEN COALESCE(ir.severity, v.severity, '') IN ('low', 'negligible', 'none') THEN 'low'
	ELSE 'medium' END`

// EffectiveExpr is the rating in force in one product, as a word.
const EffectiveExpr = `COALESCE(ir.severity, v.severity, '')`
