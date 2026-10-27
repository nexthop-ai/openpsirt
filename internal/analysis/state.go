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

// standingOutcome is the outcome of the decision standing at the occurrence of the
// finding under "f", in the product bound: one somebody agreed to, or one
// that waits on nobody and was not sent back. A decision waiting for a second
// person answers nothing yet.
var standingOutcome = `(SELECT MAX("sc"."outcome") FROM "decision_occurrence" AS "dc"
	JOIN "decision" AS "sc" ON "sc"."id" = "dc"."decision_id"
	WHERE "dc"."product_id" = ? AND "dc"."live_key" IS NOT NULL
	  AND ` + finding.DecisionOccurrenceFiledAt("dc", "f") + `
	  AND ("dc"."state" = 'approved' OR ("dc"."needs_approval" = FALSE AND "dc"."sent_back_at" IS NULL)))`

// recordedAsFlaw is whether the code finding under "f" in the product bound was recorded as a flaw.
var recordedAsFlaw = `EXISTS (SELECT 1 FROM "code_finding_flaw" AS "lh"
	WHERE "lh"."product_id" = ? AND "lh"."occurrence_identity" = "f"."occurrence_identity")`

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
func stateOf(productID int64) (string, []any) {
	return `CASE
		WHEN "f"."closed_at" IS NOT NULL THEN '` + string(Fixed) + `'
		WHEN ` + recordedAsFlaw + ` THEN '` + string(RecordedAsFlaw) + `'
		WHEN ` + standingOutcome + ` IS NOT NULL THEN ` + standingOutcome + `
		WHEN ` + ruled + ` THEN '` + string(Dismissed) + `'
		WHEN "si"."absent_run_id" IS NOT NULL THEN '` + string(NoLongerDetected) + `'
		ELSE '` + string(Open) + `' END`, []any{productID, productID, productID, productID}
}
