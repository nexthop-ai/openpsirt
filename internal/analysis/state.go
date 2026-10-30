// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// State is where a code finding stands, worked out when it is read from the finding,
// its sighting and the decision standing at its occurrence.
type State string

const (
	// Open is a code finding to be judged.
	Open State = "open"
	// NoLongerDetected is a code finding a comparable run did not see.
	NoLongerDetected State = "no-longer-detected"
	// Fixed is a code finding somebody stated was fixed.
	Fixed State = "fixed"
	// RecordedAsFlaw is a confirmed code finding recorded as a flaw here.
	RecordedAsFlaw State = "recorded-as-flaw"
	// Dismissed, NotSecurity and Confirmed are a code finding a standing decision
	// answers.
	Dismissed   State = finding.OutcomeDismissed
	NotSecurity State = finding.OutcomeNotSecurity
	Confirmed   State = finding.OutcomeConfirmed
)

// States are every state a code finding is in, in the order a code finding meets them.
func States() []State {
	return []State{Open, NoLongerDetected, Fixed, Dismissed, NotSecurity, Confirmed, RecordedAsFlaw}
}

// standingOutcomeIn is the outcome of the decision standing at the occurrence
// of the finding under "f", in the product bound: one somebody agreed to, or
// one that waits on nobody and was not sent back. A decision waiting for a
// second person answers nothing yet. It binds the product's arguments once.
func standingOutcomeIn(product productBound) string {
	return `(SELECT MAX("sc"."outcome") FROM "decision_occurrence" AS "dc"
	JOIN "decision" AS "sc" ON "sc"."id" = "dc"."decision_id"
	WHERE "dc"."product_id" = ` + product.sql + ` AND "dc"."live_key" IS NOT NULL
	  AND ` + finding.DecisionOccurrenceFiledAt("dc", "f") + `
	  AND ("dc"."state" = 'approved' OR ("dc"."needs_approval" = FALSE AND "dc"."sent_back_at" IS NULL)))`
}

// recordedAsFlawIn is whether the code finding under "f" in the product bound
// was recorded as a flaw. It binds the product's arguments once.
func recordedAsFlawIn(product productBound) string {
	return `EXISTS (SELECT 1 FROM "code_finding_flaw" AS "lh"
	WHERE "lh"."product_id" = ` + product.sql + ` AND "lh"."occurrence_identity" = "f"."occurrence_identity")`
}

// stateOf is the state of the finding under "f", whose sighting is under
// "si", in the product bound, as an expression, with
// what it binds.
//
// A flaw record comes after a closure and before everything else: the code finding is
// its flaw's now, and whatever is said of the flaw is said there.
//
// A standing decision comes before a suppression rule, which comes before absence:
// a dismissed code finding a run does not see stays dismissed and records the
// absence.
func stateOf(productID int64) (string, []any) { return stateAt(inProduct(productID)) }

// stateAt is stateOf in the product bound given: one product, or the product
// of each row's branch or tag.
func stateAt(b productBound) (string, []any) {
	return `CASE
		WHEN "f"."closed_at" IS NOT NULL THEN '` + string(Fixed) + `'
		WHEN ` + recordedAsFlawIn(b) + ` THEN '` + string(RecordedAsFlaw) + `'
		WHEN ` + standingOutcomeIn(b) + ` IS NOT NULL THEN ` + standingOutcomeIn(b) + `
		WHEN ` + ruledIn(b) + ` THEN '` + string(Dismissed) + `'
		WHEN "si"."absent_run_id" IS NOT NULL THEN '` + string(NoLongerDetected) + `'
		ELSE '` + string(Open) + `' END`, b.times(4)
}

// productBound is the product the product-bound conditions of a statement
// compare with: one product, bound as a value, or the product of the branch
// or tag under "s", for a list across products. The conditions take it rather
// than a fragment of SQL, so what they splice into a statement is one of the
// two built here.
type productBound struct {
	sql  string
	args []any
}

// inProduct is one product, bound as a value.
func inProduct(productID int64) productBound {
	return productBound{sql: "?", args: []any{productID}}
}

// eachProduct is the product of the branch or tag under "s", which binds
// nothing: each row is compared within its own product.
var eachProduct = productBound{sql: `"s"."product_id"`}

// times is what n conditions naming the product bind, in order. Binding
// nothing is nil, since the query builder warns of arguments given to a
// statement with no placeholder, an empty list included.
func (b productBound) times(n int) []any {
	if len(b.args) == 0 {
		return nil
	}
	out := make([]any, 0, n*len(b.args))
	for range n {
		out = append(out, b.args...)
	}
	return out
}
