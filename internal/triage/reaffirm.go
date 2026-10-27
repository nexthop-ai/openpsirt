// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Reaffirmation is somebody saying a lapsed decision still holds.
type Reaffirmation struct {
	// PreviousID names the decision occurrence that stopped applying — because the code
	// moved under it, not because anybody disagreed.
	//
	// Named rather than passed. Whether an agreement may be carried forward is
	// read from the row, because a caller holding a stale copy would carry one
	// that has since been withdrawn, and a caller inventing a copy would carry
	// one that never existed.
	PreviousID int64
	// Occurrence is where it is being re-made, at the versions it has now.
	Occurrence Occurrence
	// Reasoning is the fresh reason. Required: "still true" with nothing
	// behind it is what a re-affirmation becomes when it is easy enough.
	Reasoning string
	By        int64
}

// Reaffirm re-makes a decision occurrence the code moved out from under.
//
// The person who made it may re-make it, with no second approver. Two people
// already agreed to this decision; a version bump is a prompt to re-check rather
// than a new decision, and requiring full approval on every bump produces
// rubber-stamping — which costs the control its meaning everywhere, not only
// here.
//
// Two things put it back through full approval, and both fire on something
// having actually changed:
//
// Nobody having agreed to the previous decision leaves nothing to carry, and
// treating a lapse as evidence of agreement would manufacture one.
//
// A severity that has risen since means the original decision was made about a
// smaller thing, where the decision turns on how bad the issue is. What was
// agreed to was that this did not matter much; that is not an agreement about
// what it has become. A decision that the code is absent, or never runs, or that
// the fix already ships, holds however bad the issue is.
//
// A count of re-affirmations deliberately does not trigger it. That would fire
// on nothing having changed, which every other rule here refuses to do.
func (s *Store) Reaffirm(ctx context.Context, subject access.Subject, r Reaffirmation) (*DecisionOccurrence, error) {
	if !mayDecideOn(subject, r.Occurrence.ProductID, r.Occurrence.VulnerabilityID, visibilityOf(r.Occurrence)) {
		return nil, ErrNotTheirs
	}
	if r.By != subject.ID {
		return nil, refusal.Errorf("a decision is recorded as made by whoever made it")
	}

	var made *DecisionOccurrence
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		var err error
		made, err = within.reaffirm(ctx, subject, r)
		return err
	})
	if err != nil {
		return nil, s.alreadyDecided(ctx, err, []Occurrence{r.Occurrence})
	}
	return made, nil
}

// reaffirm is the whole of a re-affirmation, in one transaction.
//
// One transaction because it is one act. Written as three — read the old
// decision, write the new one, carry the agreement — a process that stopped in
// the middle left a decision standing that nobody had agreed to and that no
// review queue would ever show, because it was recorded as needing nobody.
// Everything it turns on is read in here too: the old decision's visibility, who
// proposed it, and whether its agreement still stands all decide what this may
// do, and read outside they are answers about a database that has since moved.
func (s *Store) reaffirm(ctx context.Context, subject access.Subject,
	r Reaffirmation) (*DecisionOccurrence, error) {

	previous := new(DecisionOccurrence)
	// With its argument, which is the whole of what a re-affirmation carries:
	// the row says where the earlier decision landed, and the decision says what
	// it was.
	if err := s.db.NewSelect().Model(previous).Relation("Decision").
		Where(`"de"."id" = ?`, r.PreviousID).Scan(ctx); err != nil {
		return nil, database.FromRead(err, ErrNotTheirs, fmt.Sprintf("read decision occurrence %d", r.PreviousID))
	}
	// Authorized against the row, not against what the caller said about it.
	// Checking the stated visibility would let somebody trusted only with what
	// has been disclosed re-affirm an undisclosed decision — and, because the new
	// row is written with the visibility it was authorized under, publish
	// it in the act of re-making it.
	if !mayDecideOn(subject, previous.ProductID, previous.VulnerabilityID, previous.Visibility) {
		return nil, ErrNotTheirs
	}
	// The decision being re-made has to be about the same thing. Otherwise a
	// re-affirmation is a way to attach one occurrence's agreement to another's.
	// Compared as the issue each is read as: a row filed under an issue
	// that merged into another is about the occurrence under the other.
	readAs, err := finding.IssuesOf(ctx, s.db,
		[]int64{previous.VulnerabilityID, r.Occurrence.VulnerabilityID})
	if err != nil {
		return nil, err
	}
	if previous.ProductID != r.Occurrence.ProductID ||
		readAs[previous.VulnerabilityID] != readAs[r.Occurrence.VulnerabilityID] ||
		previous.OccurrenceIdentity != r.Occurrence.OccurrenceIdentity {
		return nil, refusal.Errorf("that decision was about a different occurrence")
	}
	// Re-affirming is a right the person who made the decision has, and nobody
	// else. Without this the approver could re-affirm — becoming proposer of
	// the new decision while their own earlier agreement is carried onto it, so
	// one person ends up on both sides of a control that says they may not be.
	if previous.ProposedBy != subject.ID {
		return nil, refusal.Errorf(
			"only the person who made a decision may re-affirm it; anybody else proposes it afresh")
	}
	// And only a decision that lapsed, with nothing decided at its occurrence
	// since: the rule the list of what is yours to re-affirm holds. A
	// decision still standing carried its agreement to whatever occurrence it was
	// re-made at, and a second person never saw the new one.
	reaffirmable, err := s.yoursToReaffirm(subject).Where(`"de"."id" = ?`, previous.ID).Exists(ctx)
	if err != nil {
		return nil, fmt.Errorf("read whether that decision is yours to re-affirm: %w", err)
	}
	if !reaffirmable {
		return nil, refusal.Errorf(
			"that decision has not lapsed, or something has been decided at that occurrence since")
	}

	// And it keeps the visibility it had. A re-affirmation says the same decision
	// still holds; it is not an occasion to change who may see it.
	occurrence := r.Occurrence
	occurrence.Visibility = previous.Visibility

	// The need for a second person is decided before this is written, and
	// recorded on the decision, so a re-affirmation sent back for full approval
	// waits in the review queue rather than suppressing the finding on one
	// person's word. An agreement to carry at all, asked of the approvals
	// rather than inferred from the state. A decision lapses from Proposed as well as from
	// Approved (the code moved out from under it either way), so "it lapsed"
	// says nothing about whether anybody ever agreed to it.
	carryable, err := s.approvalToCarry(ctx, previous.DecisionID, subject.ID)
	if err != nil {
		return nil, err
	}
	// The severity judged now, read inside the transaction with everything
	// else this turns on: an advisory sweep or a retry can move the severity
	// between the request and the write, and the agreement is carried on the
	// strength of it.
	severityNow, err := s.severityOf(ctx, previous.ProductID, previous.VulnerabilityID)
	if err != nil {
		return nil, err
	}
	full := needsFullApproval(*previous, *previous.Decision, severityNow, carryable != nil)

	proposal := remade(*previous.Decision, occurrence, r.Reasoning, r.By, severityNow, full)
	// The same decision re-made, so it keeps the builds it was made on.
	proposal.MadeAs = previous.DecisionID
	// The same checks Propose makes, made here because the write is already
	// inside a transaction and Propose opens its own.
	if !mayDecideOn(subject, occurrence.ProductID, occurrence.VulnerabilityID, visibilityOf(occurrence)) {
		return nil, ErrNotTheirs
	}
	if err := proposal.valid(s.now()); err != nil {
		return nil, err
	}
	// A re-affirmation is an action of its own. It carries the earlier
	// agreement where it may, but the decision it makes is a new one.
	decision, err := s.newDecision(ctx, FindingDecision, r.By, nil, "", proposal)
	if err != nil {
		return nil, err
	}
	made, err := s.propose(ctx, decision, proposal)
	if err != nil {
		return nil, err
	}

	if full {
		return made, nil
	}

	// Carried rather than re-agreed. Recorded as an approval like any other,
	// naming the words it stands on, so what somebody reading the record sees
	// is that this was agreed to — and by whom, and when — rather than a gap
	// where an agreement should be.
	if err := s.carryApproval(ctx, made, *decision, *previous); err != nil {
		return nil, err
	}
	return made, nil
}

// remade is a decision re-made at an occurrence, under fresh reasoning.
//
// Everything the decision rests on comes with it. A re-affirmation says the same
// decision still holds, so a field the outcome requires is as required here as it
// was the first time — and dropping one does not produce a weaker decision, it
// produces a refusal: what stops it is required with the mitigations reason
// and the version is required with the already-fixed outcome.
func remade(previous Decision, at Occurrence, reasoning string, by int64, severity int, full bool) Proposal {
	return Proposal{
		Occurrence: at, Outcome: previous.Outcome,
		Justification: Justification(orEmpty(previous.Justification)),
		Mitigation:    orEmpty(previous.Mitigation),
		Scope:         scopeOf(previous.Scope),
		DeferredUntil: previous.DeferredUntil,
		CommittedTo:   previous.CommittedTo,
		UpgradeTo:     orEmpty(previous.UpgradeTo),
		FixedVersion:  orEmpty(previous.FixedVersion),
		Reasoning:     reasoning, By: by,
		SeverityCenti: severity,
		NeedsApproval: full,
	}
}

// severityOf is how bad an issue is judged to be now, in hundredths.
//
// This product's rating where somebody here has made one, and the published one
// where nobody has, worked out by the project's one rule for the number rather
// than read off a column. The product is the one the decision was made in: a
// rating another team holds is not evidence about this decision.
//
// Not the published score alone: an assessment writes the word and never the
// score, so an issue published `high` with no vector scores zero before an
// assessment and after it, and zero against zero would read as no worse after
// somebody rated it critical — the one thing this comparison exists to catch.
func (s *Store) severityOf(ctx context.Context, productID, vulnerabilityID int64) (int, error) {
	var issue struct {
		Published  string `bun:"published"`
		Assessed   string `bun:"assessed"`
		ScoreCenti int    `bun:"score_centi"`
	}
	// Read as the issue the row's own issue stands for: a merge moves
	// the published word and the product's rating to the issue kept.
	if err := s.db.NewSelect().
		TableExpr(`"vulnerability" AS "sv"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "sv"."issue_id"`).
		Join(rating.Here, productID).
		ColumnExpr(`COALESCE("v"."severity", '') AS "published"`).
		ColumnExpr(`COALESCE("ir"."severity", '') AS "assessed"`).
		ColumnExpr(`COALESCE("v"."score_centi", 0) AS "score_centi"`).
		Where(`"sv"."id" = ?`, vulnerabilityID).Scan(ctx, &issue); err != nil {
		return 0, fmt.Errorf("read how bad this is now: %w", err)
	}
	return finding.Rating{
		Published: issue.Published, Assessed: issue.Assessed, ScoreCenti: issue.ScoreCenti,
	}.Score(), nil
}

// needsFullApproval reports whether a re-affirmation is really a new decision.
func needsFullApproval(previous DecisionOccurrence, decision Decision, severityNow int, agreed bool) bool {
	// Never carried where nobody agreed in the first place. A decision that was
	// only ever proposed has nothing to carry, and treating its re-affirmation
	// as pre-agreed would manufacture an approval out of a version bump.
	//
	// Asked of the agreements rather than of the state, because a lapse is not
	// evidence of one: Lapse marks Proposed rows as well as Approved ones, so
	// a dismissal one person proposed, nobody agreed to, and a version bump
	// lapsed came back through here as pre-agreed — needing nobody, standing
	// the moment it was written, and absent from the review queue, which is
	// the whole of what the second person exists to prevent.
	if !agreed {
		return true
	}
	if turnsOnSeverity(decision) && ratedWorse(previous.SeverityCenti, severityNow) {
		return true
	}
	return false
}

// turnsOnSeverity reports whether a decision is one that how bad the issue
// is could change.
//
// Most that hide risk are. A deferral, a refusal to fix and a promise to act all accept the
// risk for a while, and the risk is the severity. An argument that nothing an
// attacker controls reaches the code, or that something already stops it, is
// weighed against what the issue lets an attacker do, and a higher rating is
// often a new way in.
//
// Three are not. Code that is absent or never runs is not dangerous at any
// severity, and a fix that already ships is there whatever the rating says.
func turnsOnSeverity(decision Decision) bool {
	// A decision that hides nothing is only strengthened by a rise, and a decision
	// about identity is not a decision about risk.
	if !decision.Outcome.HidesRisk() || decision.Outcome == Mismatched {
		return false
	}
	// A rule is rated by nobody, so nothing about a code finding rises.
	if decision.Outcome.AboutALead() {
		return false
	}
	switch decision.Outcome {
	case AlreadyFixed:
		return false
	case NotApplicable:
		if decision.Justification == nil {
			return true
		}
		return !Justification(*decision.Justification).IndifferentToSeverity()
	}
	return true
}

// approvalToCarry returns the standing agreement a re-affirmation may carry,
// or nil where there is none.
//
// Standing, and somebody else's. A withdrawn agreement is kept because who
// agreed and to what is part of the record, but carrying it forward would
// resurrect it against words nobody read; and an agreement from whoever is
// re-affirming would put one person on both sides of the control.
//
// Asked twice per re-affirmation — once to decide whether a second person is
// needed, once to write the carried agreement — and both answers have to be
// the same one, which is why it is a function rather than two queries.
func (s *Store) approvalToCarry(ctx context.Context, decisionID, notBy int64) (*Approval, error) {
	var found []Approval
	if err := s.db.NewSelect().Model(&found).
		Where(`"decision_id" = ?`, decisionID).
		Where(`"withdrawn_at" IS NULL`).
		Where(`"approved_by" <> ?`, notBy).
		Order("id DESC").Limit(1).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what agreed to that: %w", err)
	}
	if len(found) == 0 {
		return nil, nil
	}
	return &found[0], nil
}

// carryApproval records that a re-affirmed decision stands on the agreement its
// predecessor had.
func (s *Store) carryApproval(ctx context.Context, made *DecisionOccurrence, decision Decision, previous DecisionOccurrence) error {
	return s.carryApprovalTo(ctx, []*DecisionOccurrence{made}, decision, previous)
}

// carryApprovalTo is the same for every row of one act.
//
// One approval row, however many rows it stands over. An agreement is
// an agreement to a decision's words, and the decision is what an approver reads —
// written per row, one person agreeing once would appear in the record
// forty five times. The rows it takes effect on are updated together, because
// a bulk re-affirmation where half the rows stood and half waited is an
// approver having agreed to part of an argument they were shown whole.
func (s *Store) carryApprovalTo(ctx context.Context, made []*DecisionOccurrence, decision Decision,
	previous DecisionOccurrence) error {

	if len(made) == 0 {
		return nil
	}
	// The concrete path this refuses: propose, have it agreed to, revise
	// (which withdraws the agreement), let a version bump lapse it, re-affirm.
	earlier, err := s.approvalToCarry(ctx, previous.DecisionID, made[0].ProposedBy)
	if err != nil {
		return err
	}
	if earlier == nil {
		// Nothing to carry. Not a fault: a decision may have lapsed before
		// anybody agreed to it, and the decision then waits like any other —
		// which is what needsFullApproval already decided when it asked this
		// same question before the decision was written.
		return nil
	}
	if decision.RevisionID == nil {
		return refusal.Errorf("a re-affirmed decision has no reasoning to stand on")
	}
	// Asked of the earlier decision, whose words the carried agreement was given
	// to. The new decision is the re-affirmer's alone, and its approver is
	// already somebody else.
	if err := s.secondPerson(ctx, previous.DecisionID, earlier.ApprovedBy); err != nil {
		return err
	}

	now := s.now().Truncate(time.Microsecond)
	// Named as carried, not written as a fresh agreement. The reasoning on
	// this decision is the re-affirmer's own and the earlier approver has not
	// read it; what they agreed to is the earlier decision's words, and the
	// approval they gave is where those are.
	carried := &Approval{
		DecisionID: decision.ID, RevisionID: *decision.RevisionID,
		ApprovedBy: earlier.ApprovedBy, ApprovedAt: now,
		CarriedFrom: &earlier.ID,
	}
	if _, err := s.db.NewInsert().Model(carried).Exec(ctx); err != nil {
		return fmt.Errorf("carry an approval forward: %w", err)
	}
	// Guarded on the revision, the way every other approval here is. An
	// agreement is an agreement to particular words, so it only takes effect
	// while those are still the words the decision rests on — otherwise a
	// re-affirmation revised between being written and being approved would
	// stand on an agreement to text nobody read.
	ids := make([]int64, 0, len(made))
	for _, one := range made {
		ids = append(ids, one.ID)
	}
	// Every row was written as proposed in this transaction, so the state the
	// statement asks for is the state each one is in.
	if err := s.approveWhileRevised(ctx, decision, ids, "carry an approval forward",
		"the reasoning changed while this was being agreed to"); err != nil {
		return err
	}
	for _, one := range made {
		one.State = Approved
	}
	return nil
}
