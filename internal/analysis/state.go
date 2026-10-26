// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// State is where a lead stands, worked out when it is read from the finding,
// its sighting and the claim standing at its place.
type State string

const (
	// Open is a lead to be judged.
	Open State = "open"
	// NotReproduced is a lead a comparable run did not see.
	NotReproduced State = "not-reproduced"
	// Fixed is a lead somebody stated was fixed.
	Fixed State = "fixed"
	// HandedOff is a confirmed lead recorded as a flaw here.
	HandedOff State = "handed-off"
	// Dismissed, NotSecurity and Confirmed are a lead a standing claim
	// answers.
	Dismissed   State = finding.OutcomeDismissed
	NotSecurity State = finding.OutcomeNotSecurity
	Confirmed   State = finding.OutcomeConfirmed
)

// States are every state a lead is in, in the order a lead meets them.
func States() []State {
	return []State{Open, NotReproduced, Fixed, Dismissed, NotSecurity, Confirmed, HandedOff}
}

// standingOutcome is the outcome of the claim standing at the place of the
// finding under "f", in the product bound: one somebody agreed to, or one
// that waits on nobody and was not sent back. A claim waiting for a second
// person answers nothing yet.
var standingOutcome = `(SELECT MAX("sc"."outcome") FROM "decision_occurrence" AS "dc"
	JOIN "decision" AS "sc" ON "sc"."id" = "dc"."decision_id"
	WHERE "dc"."product_id" = ? AND "dc"."live_key" IS NOT NULL
	  AND ` + finding.DecisionFiledAt("dc", "f") + `
	  AND ("dc"."state" = 'approved' OR ("dc"."needs_approval" = FALSE AND "dc"."sent_back_at" IS NULL)))`

// handedOff is whether the lead under "f" in the product bound was handed off.
var handedOff = `EXISTS (SELECT 1 FROM "lead_handoff" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."occurrence_identity" = "f"."occurrence_identity")`

// stateOf is the state of the finding under "f", whose sighting is under
// "si", in the product bound, as an expression, with
// what it binds.
//
// A hand-off comes after a closure and before everything else: the lead is
// its flaw's now, and whatever is said of the flaw is said there.
//
// A standing claim comes before a standing rule, which comes before absence:
// a dismissed lead a run does not see stays dismissed and records the
// absence.
func stateOf(productID int64) (string, []any) {
	return `CASE
		WHEN "f"."closed_at" IS NOT NULL THEN '` + string(Fixed) + `'
		WHEN ` + handedOff + ` THEN '` + string(HandedOff) + `'
		WHEN ` + standingOutcome + ` IS NOT NULL THEN ` + standingOutcome + `
		WHEN ` + ruled + ` THEN '` + string(Dismissed) + `'
		WHEN "si"."absent_run_id" IS NOT NULL THEN '` + string(NotReproduced) + `'
		ELSE '` + string(Open) + `' END`, []any{productID, productID, productID, productID}
}
