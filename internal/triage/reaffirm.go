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
)

// Reaffirmation is somebody saying a lapsed claim still holds.
type Reaffirmation struct {
	// PreviousID names the decision that stopped applying — because the code
	// moved under it, not because anybody disagreed.
	//
	// Named rather than passed. Whether an agreement may be carried forward is
	// read from the row, because a caller holding a stale copy would carry one
	// that has since been withdrawn, and a caller inventing a copy would carry
	// one that never existed.
	PreviousID int64
	// Place is where it is being re-made, at the versions it has now.
	Place Place
	// Reasoning is the fresh reason. Required: "still true" with nothing
	// behind it is what a re-affirmation becomes when it is easy enough.
	Reasoning string
	By        int64
}

// Reaffirm re-makes a decision the code moved out from under.
//
// The person who made it may re-make it, with no second approver. Two people
// already agreed to this claim; a version bump is a prompt to re-check rather
// than a new claim, and requiring full approval on every bump produces
// rubber-stamping — which costs the control its meaning everywhere, not only
// here.
//
// Two things put it back through full approval, and both fire on something
// having actually changed:
//
// Nobody having agreed to the previous claim leaves nothing to carry, and
// treating a lapse as evidence of agreement would manufacture one.
//
// A severity that has risen since means the original judgment was made about a
// smaller thing, where the judgment turns on how bad the issue is. What was
// agreed to was that this did not matter much; that is not an agreement about
// what it has become. A claim that the code is absent, or never runs, or that
// the fix already ships, holds however bad the issue is.
//
// A count of re-affirmations deliberately does not trigger it. That would fire
// on nothing having changed, which every other rule here refuses to do.
func (s *Store) Reaffirm(ctx context.Context, subject access.Subject, r Reaffirmation) (*Decision, error) {
	if !mayDecideOn(subject, r.Place.ProductID, r.Place.VulnerabilityID, visibilityOf(r.Place)) {
		return nil, ErrNotTheirs
	}
	if r.By != subject.ID {
		return nil, fmt.Errorf("a decision is recorded as made by whoever made it")
	}

	var made *Decision
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		var err error
		made, err = within.reaffirm(ctx, subject, r)
		return err
	})
	if err != nil {
		return nil, s.alreadyDecided(ctx, err, []Place{r.Place})
	}
	return made, nil
}

// reaffirm is the whole of a re-affirmation, in one transaction.
//
// One transaction because it is one act. Written as three — read the old
// claim, write the new one, carry the agreement — a process that stopped in
// the middle left a claim standing that nobody had agreed to and that no
// review queue would ever show, because it was recorded as needing nobody.
// Everything it turns on is read in here too: the old claim's visibility, who
// proposed it, and whether its agreement still stands all decide what this may
// do, and read outside they are answers about a database that has since moved.
func (s *Store) reaffirm(ctx context.Context, subject access.Subject,
	r Reaffirmation) (*Decision, error) {

	previous := new(Decision)
	// With its argument, which is the whole of what a re-affirmation carries:
	// the row says where the earlier judgment landed, and the claim says what
	// it was.
	if err := s.db.NewSelect().Model(previous).Relation("Claim").
		Where("de.id = ?", r.PreviousID).Scan(ctx); err != nil {
		return nil, database.FromRead(err, ErrNotTheirs, fmt.Sprintf("read decision %d", r.PreviousID))
	}
	// Authorized against the row, not against what the caller said about it.
	// Checking the stated visibility would let somebody trusted only with what
	// has been disclosed re-affirm an undisclosed claim — and, because the new
	// decision is written with the visibility it was authorized under, publish
	// it in the act of re-making it.
	if !mayDecideOn(subject, previous.ProductID, previous.VulnerabilityID, previous.Visibility) {
		return nil, ErrNotTheirs
	}
	// The claim being re-made has to be about the same thing. Otherwise a
	// re-affirmation is a way to attach one place's agreement to another's.
	// Compared as the issue each is read as: a decision filed under an issue
	// that merged into another is about the place under the other.
	readAs, err := finding.IssuesOf(ctx, s.db,
		[]int64{previous.VulnerabilityID, r.Place.VulnerabilityID})
	if err != nil {
		return nil, err
	}
	if previous.ProductID != r.Place.ProductID ||
		readAs[previous.VulnerabilityID] != readAs[r.Place.VulnerabilityID] ||
		previous.PlaceIdentity != r.Place.PlaceIdentity {
		return nil, fmt.Errorf("that decision was about a different place")
	}
	// Re-affirming is a right the person who made the claim has, and nobody
	// else. Without this the approver could re-affirm — becoming proposer of
	// the new claim while their own earlier agreement is carried onto it, so
	// one person ends up on both sides of a control that says they may not be.
	if previous.ProposedBy != subject.ID {
		return nil, fmt.Errorf(
			"only the person who made a decision may re-affirm it; anybody else proposes it afresh")
	}

	// And it keeps the visibility it had. A re-affirmation says the same claim
	// still holds; it is not an occasion to change who may see it.
	place := r.Place
	place.Visibility = previous.Visibility

	justification := ""
	if previous.Claim.Justification != nil {
		justification = *previous.Claim.Justification
	}
	// Everything the claim rests on comes with it. A re-affirmation says the
	// same claim still holds, so a field the outcome requires is as required
	// here as it was the first time — and dropping one does not produce a
	// weaker claim, it produces a refusal: what stops it is required with the
	// mitigations reason and the version is required with the already-fixed
	// outcome, so a re-affirmation of either was refused by its own validation
	// for want of a value nobody had removed.
	mitigation := ""
	if previous.Claim.Mitigation != nil {
		mitigation = *previous.Claim.Mitigation
	}
	fixedVersion := ""
	if previous.Claim.FixedVersion != nil {
		fixedVersion = *previous.Claim.FixedVersion
	}

	// The need for a second person is decided before this is written, and
	// recorded on the claim, so a re-affirmation sent back for full approval
	// waits in the review queue rather than suppressing the finding on one
	// person's word. An agreement to carry at all, asked of the approvals
	// rather than inferred from the state. A claim lapses from Proposed as well as from
	// Approved (the code moved out from under it either way), so "it lapsed"
	// says nothing about whether anybody ever agreed to it.
	carryable, err := s.approvalToCarry(ctx, previous.ClaimID, subject.ID)
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
	full := needsFullApproval(*previous, *previous.Claim, severityNow, carryable != nil)

	proposal := Proposal{
		Place: place, Outcome: previous.Claim.Outcome,
		Justification: Justification(justification),
		Mitigation:    mitigation,
		DeferredUntil: previous.Claim.DeferredUntil,
		CommittedTo:   previous.Claim.CommittedTo,
		UpgradeTo:     orEmpty(previous.Claim.UpgradeTo),
		FixedVersion:  fixedVersion,
		Reasoning:     r.Reasoning, By: r.By,
		SeverityCenti: severityNow,
		NeedsApproval: full,
	}
	// The same checks Propose makes, made here because the write is already
	// inside a transaction and Propose opens its own.
	if !mayDecideOn(subject, place.ProductID, place.VulnerabilityID, visibilityOf(place)) {
		return nil, ErrNotTheirs
	}
	if err := proposal.valid(s.now()); err != nil {
		return nil, err
	}
	// A re-affirmation is an action of its own. It carries the earlier
	// agreement where it may, but the claim it makes is a new one.
	claim, err := s.newClaim(ctx, FindingClaim, r.By, nil, "", proposal)
	if err != nil {
		return nil, err
	}
	made, err := s.propose(ctx, claim, proposal)
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
	if err := s.carryApproval(ctx, made, *claim, *previous); err != nil {
		return nil, err
	}
	return made, nil
}

// severityOf is how bad an issue is judged to be now, in hundredths.
//
// This product's rating where somebody here has made one, and the published one
// where nobody has, worked out by the project's one rule for the number rather
// than read off a column. The product is the one the decision was made in: a
// rating another team holds is not evidence about this claim.
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
	// Read as the issue the decision's own issue stands for: a merge moves
	// the published word and the product's rating to the issue kept.
	if err := s.db.NewSelect().
		TableExpr(`"vulnerability" AS "sv"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = sv.issue_id`).
		Join(rating.Here, productID).
		ColumnExpr(`COALESCE(v.severity, '') AS "published"`).
		ColumnExpr(`COALESCE(ir.severity, '') AS "assessed"`).
		ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
		Where("sv.id = ?", vulnerabilityID).Scan(ctx, &issue); err != nil {
		return 0, fmt.Errorf("read how bad this is now: %w", err)
	}
	return finding.Rating{
		Published: issue.Published, Assessed: issue.Assessed, ScoreCenti: issue.ScoreCenti,
	}.Score(), nil
}

// needsFullApproval reports whether a re-affirmation is really a new claim.
func needsFullApproval(previous Decision, claim Claim, severityNow int, agreed bool) bool {
	// Never carried where nobody agreed in the first place. A claim that was
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
	if turnsOnSeverity(claim) && ratedWorse(previous.SeverityCenti, severityNow) {
		return true
	}
	return false
}

// turnsOnSeverity reports whether a claim is a judgment that how bad the issue
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
func turnsOnSeverity(claim Claim) bool {
	// A claim that hides nothing is only strengthened by a rise, and a claim
	// about identity is not a judgment about risk.
	if !claim.Outcome.HidesRisk() || claim.Outcome == Mismatched {
		return false
	}
	switch claim.Outcome {
	case AlreadyFixed:
		return false
	case NotApplicable:
		if claim.Justification == nil {
			return true
		}
		return !Justification(*claim.Justification).IndifferentToSeverity()
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
func (s *Store) approvalToCarry(ctx context.Context, claimID, notBy int64) (*Approval, error) {
	var found []Approval
	if err := s.db.NewSelect().Model(&found).
		Where("claim_id = ?", claimID).
		Where("withdrawn_at IS NULL").
		Where("approved_by <> ?", notBy).
		Order("id DESC").Limit(1).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what agreed to that: %w", err)
	}
	if len(found) == 0 {
		return nil, nil
	}
	return &found[0], nil
}

// carryApproval records that a re-affirmed claim stands on the agreement its
// predecessor had.
func (s *Store) carryApproval(ctx context.Context, made *Decision, claim Claim, previous Decision) error {
	return s.carryApprovalTo(ctx, []*Decision{made}, claim, previous)
}

// carryApprovalTo is the same for every row of one act.
//
// One approval row, however many decisions it stands over. An agreement is
// an agreement to a claim's words, and the claim is what an approver reads —
// written per decision, one person agreeing once would appear in the record
// forty five times. The rows it takes effect on are updated together, because
// a bulk re-affirmation where half the rows stood and half waited is an
// approver having agreed to part of an argument they were shown whole.
func (s *Store) carryApprovalTo(ctx context.Context, made []*Decision, claim Claim,
	previous Decision) error {

	if len(made) == 0 {
		return nil
	}
	// The concrete path this refuses: propose, have it agreed to, revise
	// (which withdraws the agreement), let a version bump lapse it, re-affirm.
	earlier, err := s.approvalToCarry(ctx, previous.ClaimID, made[0].ProposedBy)
	if err != nil {
		return err
	}
	if earlier == nil {
		// Nothing to carry. Not a fault: a decision may have lapsed before
		// anybody agreed to it, and the claim then waits like any other —
		// which is what needsFullApproval already decided when it asked this
		// same question before the claim was written.
		return nil
	}
	if claim.RevisionID == nil {
		return fmt.Errorf("a re-affirmed claim has no reasoning to stand on")
	}

	now := s.now().Truncate(time.Microsecond)
	// Named as carried, not written as a fresh agreement. The reasoning on
	// this claim is the re-affirmer's own and the earlier approver has not
	// read it; what they agreed to is the earlier claim's words, and the
	// approval they gave is where those are.
	carried := &Approval{
		ClaimID: claim.ID, RevisionID: *claim.RevisionID,
		ApprovedBy: earlier.ApprovedBy, ApprovedAt: now,
		CarriedFrom: &earlier.ID,
	}
	if _, err := s.db.NewInsert().Model(carried).Exec(ctx); err != nil {
		return fmt.Errorf("carry an approval forward: %w", err)
	}
	// Guarded on the revision, the way every other approval here is. An
	// agreement is an agreement to particular words, so it only takes effect
	// while those are still the words the claim rests on — otherwise a
	// re-affirmation revised between being written and being approved would
	// stand on an agreement to text nobody read.
	ids := make([]int64, 0, len(made))
	for _, one := range made {
		ids = append(ids, one.ID)
	}
	result, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set("state = ?", Approved).
		Where("id IN (?)", bun.List(ids)).
		Where(`EXISTS (SELECT 1 FROM "claim" AS "ac" WHERE ac.id = ? AND ac.revision_id = ?)`,
			claim.ID, *claim.RevisionID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("carry an approval forward: %w", err)
	}
	changed, err := database.Affected(result)
	if err != nil {
		return fmt.Errorf("carry an approval forward: %w", err)
	}
	if changed != int64(len(ids)) {
		return fmt.Errorf("the reasoning changed while this was being agreed to")
	}
	for _, one := range made {
		one.State = Approved
	}
	return nil
}
