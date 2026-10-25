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
	// Baseline is a lead in its series' first comparable run in the product,
	// tracked and searchable and in nobody's queue.
	Baseline State = "baseline"
	// Open is a lead to be judged.
	Open State = "open"
	// NotReproduced is a lead a comparable run did not see.
	NotReproduced State = "not-reproduced"
	// Fixed is a lead somebody stated was fixed.
	Fixed State = "fixed"
	// Dismissed, NotSecurity and Confirmed are a lead a standing claim
	// answers.
	Dismissed   State = finding.OutcomeDismissed
	NotSecurity State = finding.OutcomeNotSecurity
	Confirmed   State = finding.OutcomeConfirmed
)

// States are every state a lead is in, in the order a lead meets them.
func States() []State {
	return []State{Baseline, Open, NotReproduced, Fixed, Dismissed, NotSecurity, Confirmed}
}

// standingOutcome is the outcome of the claim standing at the place of the
// finding under "f", in the product bound: one somebody agreed to, or one
// that waits on nobody and was not sent back. A claim waiting for a second
// person answers nothing yet.
var standingOutcome = `(SELECT MAX("sc"."outcome") FROM "decision" AS "dc"
	JOIN "claim" AS "sc" ON "sc"."id" = "dc"."claim_id"
	WHERE "dc"."product_id" = ? AND "dc"."live_key" IS NOT NULL
	  AND ` + finding.DecisionFiledAt("dc", "f") + `
	  AND ("dc"."state" = 'approved' OR ("dc"."needs_approval" = FALSE AND "dc"."sent_back_at" IS NULL)))`

// stateOf is the state of the finding under "f", whose sighting is under
// "si", in the product bound, as an expression, with what it binds.
//
// A standing claim comes before absence: a dismissed lead a run does not see
// stays dismissed and records the absence. Absence comes before the
// baseline, because a baseline lead nobody sees is no longer anything to work.
func stateOf(productID int64) (string, []any) {
	return `CASE
		WHEN "f"."closed_at" IS NOT NULL THEN '` + string(Fixed) + `'
		WHEN ` + standingOutcome + ` IS NOT NULL THEN ` + standingOutcome + `
		WHEN "si"."absent_run_id" IS NOT NULL THEN '` + string(NotReproduced) + `'
		WHEN "si"."baseline" = TRUE THEN '` + string(Baseline) + `'
		ELSE '` + string(Open) + `' END`, []any{productID, productID}
}
