// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/triage"
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

// notFixed keeps a read to the findings in every state but fixed, the ones
// still open on their build. It is no state of its own and is never listed.
const notFixed State = "not-fixed"

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

// inState keeps a statement over the finding under "f", whose sighting is
// under "si" and whose result is under "ar", to the findings of the scope
// standing in a state: stateAt equal to want, as conditions.
//
// Conditions, never a test of the state worked out, because a planner has no
// statistics on an expression: PostgreSQL guessed that one row in two hundred
// matched, planned the joins after it for a handful of rows, and took 8.7 s
// for the queue's page of 8,000 code findings, against 0.1 s.
func (scope Scope) inState(db bun.IDB, want State) func(*bun.SelectQuery) *bun.SelectQuery {
	b := scope.bound()
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		if want == Fixed {
			return q.Where(`"f"."closed_at" IS NOT NULL`)
		}
		q = q.Where(`"f"."closed_at" IS NULL`)
		if want == notFixed {
			return q
		}
		if want == RecordedAsFlaw {
			return q.Where(recordedAsFlawIn(b), b.times(1)...)
		}
		q = q.Where(`NOT `+recordedAsFlawIn(b), b.times(1)...)
		switch want {
		case Dismissed:
			return q.Where(`(`+standingOutcomeIn(b)+` = ? OR ("f"."id" NOT IN (?) AND `+ruledIn(b)+`))`,
				append(append(append(b.times(1), string(Dismissed)), scope.decidedIn(db, standing)), b.times(1)...)...)
		case NotSecurity, Confirmed:
			return q.Where(standingOutcomeIn(b)+` = ?`, append(b.times(1), string(want))...)
		case NoLongerDetected, Open:
			q = q.Where(`"f"."id" NOT IN (?)`, scope.decidedIn(db, standing)).Where(`NOT `+ruledIn(b), b.times(1)...)
			if want == Open {
				return q.Where(`"si"."absent_run_id" IS NULL`)
			}
			return q.Where(`"si"."absent_run_id" IS NOT NULL`)
		}
		return q.Where("1 = 0")
	}
}

// notWaiting keeps a statement over the finding under "f" to those of the
// scope no decision waits on a second person about, as a condition for the
// reason inState gives.
func (scope Scope) notWaiting(db bun.IDB) func(*bun.SelectQuery) *bun.SelectQuery {
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.Where(`"f"."id" NOT IN (?)`, scope.decidedIn(db, waiting))
	}
}

// decided is which decisions at an occurrence decidedIn reads.
type decided bool

const (
	// standing is a decision that answers: agreed to, or waiting on nobody
	// and not sent back. standingOutcomeIn reads the same, and every
	// decision has an outcome.
	standing decided = false
	// waiting is a decision proposed and waiting on a second person, as
	// waitingDecision reads it.
	waiting decided = true
)

// decidedIn is the open code findings of the scope's products at whose
// occurrence, filed under the same issue, a decision of the finding's own
// product stands or waits, as a set asked of each row by identifier. A
// decision bears only on an open finding.
//
// Read from the decisions, which are few, to the code findings they reach by
// occurrence, and to their builds by key alone, so the decisions are the one
// place an engine can start. Asked of each row as NOT EXISTS, PostgreSQL 16
// read every decision of the product once per code finding, 502 ms for time
// to judge against 163 ms, and every other form was planned by some engine
// through every decision or every open finding of a build
// (design-docs/analysis-measurements.md § Code finding queue).
func (scope Scope) decidedIn(db bun.IDB, which decided) *bun.SelectQuery {
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	products, productArgs := scope.productIn(`"de"."product_id"`)
	q := db.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).
		Join(`JOIN "vulnerability" AS "dv" ON "dv"."id" = "de"."vulnerability_id"`).
		Join(`JOIN "finding" AS "f" ON `+finding.DecisionOccurrenceOf("f")).
		Join(`JOIN "build" AS "t" ON "t"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "s" ON "s"."id" = "t"."branch_or_tag_id"`).
		ColumnExpr(`"f"."id"`).
		Where(products, productArgs...).
		Where(`"de"."live_key" IS NOT NULL`).
		Where(`"s"."product_id" = "de"."product_id"`).
		Where(`"f"."closed_at" IS NULL`).
		Where(kinds, kindArgs...)
	if which == waiting {
		q = q.Where(`"de"."state" = ? AND "de"."needs_approval" = TRUE AND "de"."sent_back_at" IS NULL`,
			string(triage.Proposed))
	} else {
		q = q.Where(`("de"."state" = 'approved' OR ("de"."needs_approval" = FALSE AND "de"."sent_back_at" IS NULL))`)
	}
	return identifiers(db, q.GroupExpr(`"f"."id"`))
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
