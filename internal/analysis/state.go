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
	// tracked and searchable and in nobody's queue until it is escalated.
	Baseline State = "baseline"
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
	return []State{Baseline, Open, NotReproduced, Fixed, Dismissed, NotSecurity, Confirmed, HandedOff}
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

// escalated is whether the finding under "f", whose result is under "ar", is
// out of the baseline in the product bound: somebody pulled its lead in, its
// path is under one the product marked important, or another analyzer
// reports the same flaw on its build.
var escalated = `(` + corroborated + `
	OR EXISTS (SELECT 1 FROM "lead_escalation" AS "le"
		WHERE "le"."product_id" = ? AND "le"."place_identity" = "f"."place_identity")
	OR EXISTS (SELECT 1 FROM "lead_important_path" AS "ip"
		WHERE "ip"."product_id" = ? AND ("ip"."prefix" = "ar"."path"
		  OR SUBSTR("ar"."path", 1, "ip"."under_length") = "ip"."under")))`

// handedOff is whether the lead under "f" in the product bound was handed off.
var handedOff = `EXISTS (SELECT 1 FROM "lead_handoff" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."place_identity" = "f"."place_identity")`

// stateOf is the state of the finding under "f", whose sighting is under
// "si" and result under "ar", in the product bound, as an expression, with
// what it binds.
//
// A hand-off comes after a closure and before everything else: the lead is
// its flaw's now, and whatever is said of the flaw is said there.
//
// A standing claim comes before a standing rule, which comes before absence:
// a dismissed lead a run does not see stays dismissed and records the
// absence. Absence comes before the
// baseline, because a baseline lead nobody sees is no longer anything to work.
func stateOf(productID int64) (string, []any) {
	return `CASE
		WHEN "f"."closed_at" IS NOT NULL THEN '` + string(Fixed) + `'
		WHEN ` + handedOff + ` THEN '` + string(HandedOff) + `'
		WHEN ` + standingOutcome + ` IS NOT NULL THEN ` + standingOutcome + `
		WHEN ` + ruled + ` THEN '` + string(Dismissed) + `'
		WHEN "si"."absent_run_id" IS NOT NULL THEN '` + string(NotReproduced) + `'
		WHEN "si"."baseline" = TRUE AND NOT ` + escalated + ` THEN '` + string(Baseline) + `'
		ELSE '` + string(Open) + `' END`, []any{productID, productID, productID, productID, productID, productID}
}
