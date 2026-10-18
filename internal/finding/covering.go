// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Covering is what one wholly covered group of places stands under: the one
// outcome every open place in it was decided with, and the earliest decision
// among them.
//
// Both documents a customer reads ask it — the VEX document of one build per
// component, and an advisory per release — and one spelling of the rule keeps
// the two from saying different things about the same places.
type Covering struct {
	Outcome   string `bun:"outcome"`
	DecidedBy int64  `bun:"decided_by"`
}

// Reader is which document a coverage is read for, which decides the outcomes
// that cover a place.
type Reader int

const (
	// ForStatements is the VEX document of one build. A claim that will not
	// be fixed covers a place only where it names what a holder can do
	// instead: the format requires an action on an affected statement, so one
	// without a mitigation has nothing to publish and falls through to
	// silence.
	ForStatements Reader = iota
	// ForReleases is an advisory, release by release. A claim that will not
	// be fixed covers a place whether or not it names a mitigation, because
	// the document says no fix is planned there either way.
	ForReleases
)

// StatedOutcomes is every outcome that covers a place for some reader, which
// is every outcome a published document states.
func StatedOutcomes() []string {
	return []string{OutcomeNotApplicable, OutcomeMismatched, OutcomeAlreadyFixed, OutcomeWontFix}
}

// coveringOutcomes is the outcomes that cover a place for one reader: every
// stated outcome, and a claim that will not be fixed only where it names a
// mitigation for a reader that publishes one.
func coveringOutcomes(reader Reader) string {
	wontFix := `("cl"."outcome" = '` + OutcomeWontFix + `' AND COALESCE("cl"."mitigation", '') <> '')`
	if reader == ForReleases {
		wontFix = `"cl"."outcome" = '` + OutcomeWontFix + `'`
	}
	var plain []string
	for _, outcome := range StatedOutcomes() {
		if outcome != OutcomeWontFix {
			plain = append(plain, "'"+outcome+"'")
		}
	}
	return `("cl"."outcome" IN (` + strings.Join(plain, ", ") + `) OR ` + wontFix + `)`
}

// WhollyCovered narrows a grouped read of findings to the groups whose every
// open place is covered by approved, live decisions agreeing on one outcome,
// and adds that outcome and the earliest decision as the columns Covering
// reads.
//
// The read is over findings `f`, with their component `c` and their consumer
// `uc` already joined, filtered to the findings its caller asks about and
// grouped by what one statement is about. This adds the decision `de` beside
// the issue it was filed under `dv`, and the claim it applies `cl`.
//
// A decision is read at the visibilities given, which are the ones the
// findings are read at: a decision carries the visibility of the finding it was
// made about.
//
// Approved, and not merely in force. A proposal needing nobody is in force on
// the screens here, and a published document carries only what a second
// person agreed to. Every outcome that covers a place hides risk, which always
// needs one, so the two agree today; the narrower word keeps them apart if
// that ever moves.
//
// The joins are left and the outcome test is part of the join rather than a
// filter, because what the counting asks is whether every open place is
// decided: a place nobody decided contributes a row with no claim, and a
// filter would drop it. One dismissal at one place speaks for a component open
// at forty-four others otherwise.
//
// The earliest decision is the claim that has stood longest and the one a
// reader can check against the record. A decision's identifier is assigned when
// it is written, so the lowest is the first written. The words are read off
// that one decision afterwards rather than taken column by column: a minimum
// per column composes a statement from several claims that no record ever
// held.
func WhollyCovered(q *bun.SelectQuery, productID int64,
	visible []access.Visibility, reader Reader) *bun.SelectQuery {

	return covered(q, productID, visible, reader).
		Having(`COUNT("cl"."id") = COUNT(*)`).
		Having(`COUNT(DISTINCT "cl"."outcome") = 1`)
}

// covered joins each open finding of a grouped read to the approved, live
// decisions covering it for one reader, and adds the outcome and the earliest
// decision as the columns Covering reads. Safe as an aggregate only where the
// caller refuses a group whose places disagree about the outcome.
func covered(q *bun.SelectQuery, productID int64, visible []access.Visibility,
	reader Reader) *bun.SelectQuery {

	return q.
		Join(`LEFT JOIN (`+Decisions+`) ON `+DecisionAt("?")+`
			AND "de"."state" = 'approved'
			AND "de"."live_key" IS NOT NULL
			AND "de"."visibility" IN (?)
			AND `+keyMatchesOn("de", `(SELECT "mc"."outcome" FROM "claim" AS "mc"
				WHERE "mc"."id" = "de"."claim_id")`), productID, bun.List(visible)).
		Join(`LEFT JOIN "claim" AS "cl" ON "cl"."id" = "de"."claim_id" AND ` + coveringOutcomes(reader)).
		ColumnExpr(`MIN("cl"."outcome") AS "outcome"`).
		ColumnExpr(`MIN("de"."id") AS "decided_by"`).
		Where(`"f"."closed_at" IS NULL`)
}

// AffectedOutcomes is every outcome that says an issue applies and stays: a
// claim that it does, the two that promise work, and a claim that it will not
// be fixed.
func AffectedOutcomes() []string {
	return []string{OutcomeAffected, OutcomeUpgradeNeeded, OutcomePatchNeeded, OutcomeWontFix}
}

// Affected is what one group of places wholly under claims that the issue
// applies stands under: the least and the greatest of their outcomes, which
// are equal where every place says the same, and the earliest decision.
type Affected struct {
	Least     string `bun:"least"`
	Greatest  string `bun:"greatest"`
	DecidedBy int64  `bun:"decided_by"`
}

// WhollyAffected narrows a grouped read of findings to the groups whose every
// open place stands under a decision in force that says the issue applies,
// and adds the columns Affected reads.
//
// In force rather than approved. Saying an issue applies hides nothing, so a
// claim of it needs nobody, and the review that guards a dismissal has nothing
// to guard here. The read is over findings `f` grouped by what one statement
// is about, as WhollyCovered's is.
func WhollyAffected(q *bun.SelectQuery, productID int64, visible []access.Visibility) *bun.SelectQuery {
	standing, args := InForce()
	quoted := make([]string, 0, len(AffectedOutcomes()))
	for _, outcome := range AffectedOutcomes() {
		quoted = append(quoted, "'"+outcome+"'")
	}
	bound := append([]any{productID}, args...)
	bound = append(bound, bun.List(visible))
	return q.
		Join(`LEFT JOIN (`+Decisions+`) ON `+DecisionAt("?")+`
			AND `+standing+`
			AND "de"."live_key" IS NOT NULL
			AND "de"."visibility" IN (?)
			AND `+keyMatchesOn("de", `(SELECT "mc"."outcome" FROM "claim" AS "mc"
				WHERE "mc"."id" = "de"."claim_id")`), bound...).
		Join(`LEFT JOIN "claim" AS "cl" ON "cl"."id" = "de"."claim_id" AND "cl"."outcome" IN (` +
			strings.Join(quoted, ", ") + `)`).
		ColumnExpr(`MIN("cl"."outcome") AS "least"`).
		ColumnExpr(`MAX("cl"."outcome") AS "greatest"`).
		ColumnExpr(`MIN("de"."id") AS "decided_by"`).
		Where(`"f"."closed_at" IS NULL`).
		Having(`COUNT("cl"."id") = COUNT(*)`)
}

// Stated is what one decision claims, as a published statement repeats it.
type Stated struct {
	// Outcome is what the claim says.
	Outcome string
	// Justification is the reason, in the vocabulary both formats share.
	Justification string
	// Mitigation is what stops the flaw, where somebody named it.
	Mitigation string
	// Scope is whom a published statement holds for, where the claim states
	// it, and empty where the outcome and the reason decide.
	Scope      string
	ProposedAt time.Time
}

// StatedBy reads what each of these decisions states for publication.
//
// One row per decision rather than a column at a time: the reason, the
// mitigation and the moment come from one claim, or a document says one thing
// in the field a machine reads and another in the field a person does.
//
// The reasoning is not read here at all. It is written for a second person
// inside this deployment, and the surest way for it not to be published is for
// the read that builds a published document never to fetch it.
func StatedBy(ctx context.Context, db bun.IDB, decisions []int64) (map[int64]Stated, error) {
	out := map[int64]Stated{}
	if len(decisions) == 0 {
		return out, nil
	}
	var rows []struct {
		ID            int64     `bun:"id"`
		Outcome       string    `bun:"outcome"`
		Justification string    `bun:"justification"`
		Mitigation    string    `bun:"mitigation"`
		Scope         string    `bun:"scope"`
		ProposedAt    time.Time `bun:"proposed_at"`
	}
	where, args := database.InAnyOf(`"de"."id"`, decisions)
	if err := db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "claim" AS "cl" ON "cl"."id" = "de"."claim_id"`).
		ColumnExpr(`"de"."id" AS "id"`).
		ColumnExpr(`"cl"."outcome" AS "outcome"`).
		ColumnExpr(`COALESCE("cl"."justification", '') AS "justification"`).
		ColumnExpr(`COALESCE("cl"."mitigation", '') AS "mitigation"`).
		ColumnExpr(`COALESCE("cl"."scope", '') AS "scope"`).
		ColumnExpr(`"de"."proposed_at" AS "proposed_at"`).
		Where(where, args...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what these claims say: %w", err)
	}
	for _, row := range rows {
		out[row.ID] = Stated{
			Outcome: row.Outcome, Justification: row.Justification, Mitigation: row.Mitigation,
			Scope: row.Scope, ProposedAt: row.ProposedAt,
		}
	}
	return out, nil
}
