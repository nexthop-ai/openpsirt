// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
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
// smaller thing. What was agreed to was that this did not matter much; that is
// not an agreement about what it has become.
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
		return nil, ErrNotTheirs
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
	if previous.ProductID != r.Place.ProductID ||
		previous.VulnerabilityID != r.Place.VulnerabilityID ||
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
	// recorded on the claim. Without it the claim was stored as needing nobody
	// — so a re-affirmation sent back for full approval suppressed the finding
	// the moment it was made and never appeared in the review queue, which is
	// one person's action producing a live dismissal no second person ever
	// sees. An agreement to carry at all, asked of the approvals rather than
	// inferred from the state. A claim lapses from Proposed as well as from
	// Approved (the code moved out from under it either way), so "it lapsed"
	// says nothing about whether anybody ever agreed to it.
	carryable, err := s.approvalToCarry(ctx, previous.ClaimID, subject.ID)
	if err != nil {
		return nil, err
	}
	// The severity judged now, read here with everything else this
	// turns on. Passed in by the caller it was a number from before the
	// transaction opened, so an advisory sweep raising the severity in
	// between — or a retry running against a database that has moved — carried
	// the old agreement forward on the strength of a figure that is gone. The
	// docstring above already said everything it turns on is read in here.
	severityNow, err := s.severityOf(ctx, previous.ProductID, previous.VulnerabilityID)
	if err != nil {
		return nil, err
	}
	full := needsFullApproval(*previous, severityNow, carryable != nil)

	proposal := Proposal{
		Place: place, Outcome: previous.Claim.Outcome,
		Justification: Justification(justification),
		Mitigation:    mitigation,
		DeferredUntil: previous.Claim.DeferredUntil,
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
// It read `score_centi` alone, which is the published score and nothing else:
// an assessment writes the word and never that column, so an issue published
// `high` with no vector scored zero before the assessment and zero after it.
// Zero against zero is "no worse than when it was agreed to", so a dismissal
// agreed once was re-affirmed with nobody else after somebody had rated the
// issue critical — which is the one thing this comparison exists to catch.
func (s *Store) severityOf(ctx context.Context, productID, vulnerabilityID int64) (int, error) {
	var issue struct {
		Published  string `bun:"published"`
		Assessed   string `bun:"assessed"`
		ScoreCenti int    `bun:"score_centi"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"vulnerability" AS "v"`).
		Join(rating.Here, productID).
		ColumnExpr(`COALESCE(v.severity, '') AS "published"`).
		ColumnExpr(`COALESCE(ir.severity, '') AS "assessed"`).
		ColumnExpr(`COALESCE(v.score_centi, 0) AS "score_centi"`).
		Where("v.id = ?", vulnerabilityID).Scan(ctx, &issue); err != nil {
		return 0, fmt.Errorf("read how bad this is now: %w", err)
	}
	return finding.Rating{
		Published: issue.Published, Assessed: issue.Assessed, ScoreCenti: issue.ScoreCenti,
	}.Score(), nil
}

// needsFullApproval reports whether a re-affirmation is really a new claim.
func needsFullApproval(previous Decision, severityNow int, agreed bool) bool {
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
	if severityNow > previous.SeverityAtApproval() {
		return true
	}
	return false
}

// SeverityAtApproval is how bad this was judged to be when it was agreed to.
//
// Stored with the decision rather than read from the issue now, which is the
// whole point: the question is whether it has risen *since*, and an issue's
// severity is rewritten in place as reports revise it.
func (d Decision) SeverityAtApproval() int {
	if d.SeverityCenti == nil {
		return 0
	}
	return *d.SeverityCenti
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

type Lapsed struct {
	// Rows is how many decisions stopped applying.
	Rows int64
	// Told is who to tell, once each.
	Told []ForPerson
}

// Lapse marks the decisions this target's contents have moved out from under.
//
// A decision is stored against the upstream versions it was made about. When
// those versions move it stops applying, and that much is automatic, because
// what applies is matched on the versions. What is not automatic is anybody
// finding out. Without this the finding simply reappears as though nobody had
// ever looked at it, with the reasoning stranded on a row nothing points at —
// which is the outcome that keeping the old decision exists to prevent.
//
// Run after a scan records what it found, because that is when the versions
// have just changed. It is one statement rather than one per place: a real
// image holds tens of thousands of places, and a sweep costing a write per
// place is a sweep somebody turns off.
//
// A decision covering nothing in the product is not lapsed. A component
// that is gone altogether closed its findings and there is nothing to ask
// anybody about, where a component still present at a different version is
// exactly the question somebody has to answer again.
//
// And covering is asked of the product, not of this build. A decision is a
// lookup shared by every build whose code matches it: one release stream
// moving to a new version while another still ships the old one leaves the
// decision covering the other, and a judgment about code that is still there
// is not one anybody needs to make again. It lapses when the last build
// holding its versions moves — which the sweep of that build finds, because a
// sweep still asks only about the places this build has open.
//
// Only this build's product is swept. A place is a pair of names, and the same
// pair sits in other products; their decisions are theirs. Lapsed is what one
// sweep found the code had moved out from under, and who is waiting to hear
// about it.
//
// A lapse is the other outcome a proposer is told about: it hands the work
// back to them, having taken a judgment they made out of force, and nothing
// they did caused it.
func (s *Store) Lapse(ctx context.Context, targetID int64) (Lapsed, error) {
	// Every open finding of this target at the decision's place, with the
	// versions it currently has — stated the same way the decision was written
	// against them, from the same expression, so that a decision cannot lapse
	// on one path and stand on the other.
	openHere := func(db bun.IDB) *bun.SelectQuery {
		return db.NewSelect().
			ColumnExpr("1").
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
			Where("f.target_id = ?", targetID).
			Where("f.closed_at IS NULL").
			Where("f.vulnerability_id = de.vulnerability_id").
			Where("f.place_identity = de.place_identity")
	}
	matching := "COALESCE(de.component_upstream_version, '') = " + finding.ComponentUpstreamExpr +
		" AND COALESCE(de.consumer_upstream_version, '') = " + finding.ConsumerUpstreamExpr

	// Any open finding in the decision's product, in any build, still at the
	// versions it was decided about.
	stillCovered := func(db bun.IDB) *bun.SelectQuery {
		return db.NewSelect().
			ColumnExpr("1").
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			Where("st.product_id = de.product_id").
			Where("f.closed_at IS NULL").
			Where("f.vulnerability_id = de.vulnerability_id").
			Where("f.place_identity = de.place_identity").
			Where(matching)
	}

	// Still found here, at versions that are not the ones this was decided
	// about, and no longer found at those versions anywhere in the product.
	// Absent and empty are the same answer on the finding's side, so a
	// decision recorded against no version matches a component stating none.
	lapsable := func(db bun.IDB) *bun.SelectQuery {
		return db.NewSelect().Model((*Decision)(nil)).
			ColumnExpr("de.id").
			Where("de.state IN (?, ?)", Proposed, Approved).
			// A claim about the match rather than about the version does not
			// stop applying when the version moves. A bump does not make a
			// wrong match right, and lapsing one would hand the same wrong
			// match back at every point release.
			Where(`NOT EXISTS (SELECT 1 FROM "claim" AS "lc"`+
				` WHERE lc.id = de.claim_id AND lc.outcome = ?)`, Mismatched).
			Where("de.product_id = (?)", db.NewSelect().
				ColumnExpr("st.product_id").
				TableExpr(`"target" AS "tg"`).
				Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
				Where("tg.id = ?", targetID)).
			Where("EXISTS (?)", openHere(db).Where("NOT ("+matching+")")).
			Where("NOT EXISTS (?)", stillCovered(db)).
			OrderExpr("de.id").
			Limit(database.InBulk.Most)
	}

	db, err := s.pool()
	if err != nil {
		return Lapsed{}, err
	}

	// Marked and read back as one act, a bounded batch at a time. It was
	// three statements on the pool with nothing around them: a crash between
	// the update and the read left rows lapsed with nobody told, which is the
	// outcome marking a lapse exists to prevent. And the rows were identified
	// on the way back by the timestamp the update wrote, under a comment
	// saying two sweeps could not read each other's rows because the product
	// is this target's — two targets of one product share a product, so two
	// scans finishing together read each other's rows and told every proposer
	// twice.
	//
	// Identified by identifier now, which is what makes each pass's rows its
	// own. Batched because a sweep over a real image can lapse thousands at
	// once and a statement naming every one of them is a statement whose size
	// is the estate's.
	out := Lapsed{}
	seen := map[int64]bool{}
	for {
		var moved int64
		var lapsed []int64
		if err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
			moved, lapsed = 0, nil
			var ids []int64
			if err := lapsable(tx).Scan(ctx, &ids); err != nil {
				return fmt.Errorf("read what the code moved out from under: %w", err)
			}
			if len(ids) == 0 {
				return nil
			}
			moment := s.now().Truncate(time.Microsecond)
			result, err := tx.NewUpdate().Model((*Decision)(nil)).
				Set("state = ?", LapsedState).
				Set("ended_at = ?", moment).
				// Released for the same reason a withdrawal is: the code
				// moved out from under this, so it covers nothing, and
				// somebody has to be able to decide about what is there now.
				Set("live_key = ?", nil).
				Where("de.id IN (?)", bun.List(ids)).
				// Re-asserted, so a row another sweep took in between is not
				// counted here as well.
				Where("de.state IN (?, ?)", Proposed, Approved).
				Exec(ctx)
			if err != nil {
				return fmt.Errorf("mark what the code moved out from under: %w", err)
			}
			n, err := database.Affected(result)
			if err != nil {
				return fmt.Errorf("mark what the code moved out from under: %w", err)
			}
			moved = n
			// The people to tell, read back inside the same act. The
			// identifiers are this pass's own, so nothing another sweep marked
			// is in it.
			if err := tx.NewSelect().Model((*Decision)(nil)).
				ColumnExpr("de.id").
				Where("de.id IN (?)", bun.List(ids)).
				Where("de.state = ?", LapsedState).
				Where("de.ended_at = ?", moment).
				Scan(ctx, &lapsed); err != nil {
				return fmt.Errorf("read what lapsed: %w", err)
			}
			return nil
		}); err != nil {
			return Lapsed{}, err
		}
		if len(lapsed) == 0 && moved == 0 {
			break
		}
		out.Rows += moved
		fresh := make([]int64, 0, len(lapsed))
		for _, id := range lapsed {
			if seen[id] {
				continue
			}
			seen[id] = true
			fresh = append(fresh, id)
		}
		if len(fresh) == 0 {
			break
		}
		told, err := s.proposersOf(ctx, fresh)
		if err != nil {
			return Lapsed{}, err
		}
		out.Told = append(out.Told, told...)
	}
	if out.Rows == 0 && len(out.Told) > 0 {
		out.Rows = int64(len(out.Told))
	}
	return out, nil
}

// Carried is what a new line would inherit from an existing one.
//
// Four buckets, because they need four different things from a person. What
// already applies needs nothing. What moved needs a fresh answer, and gets the
// old reasoning to start from. A postponement is a scheduling judgment about a
// release rather than a claim about code, so it is offered separately. And
// what covers nothing there is left behind.
type Carried struct {
	// Applying reach the new line by matching. Nothing to choose.
	Applying int
	// Moved held a claim at a version the new line does not have. Each comes
	// across as a proposal carrying the old words — never as a decision,
	// because the version moved and the old conclusion is not a conclusion
	// about the new code.
	Moved []Inherited
	// Postponed were deferrals. "Not this sprint" was about that sprint, and
	// carrying it silently gives a new line expiry dates nobody chose.
	Postponed []Inherited
	// Absent is how many cover nothing in the new line at all.
	Absent int
}

// Inherited is one claim a new line could take on.
type Inherited struct {
	DecisionID    int64
	Vulnerability string
	Component     string
	Outcome       Outcome
	Was           string
	Now           string
	Reasoning     string
	// DeferredDays is how long this has already been put off, across every
	// line it has been carried through. The number that decides whether
	// carrying it again is reasonable.
	DeferredDays int
}

// WouldCarry reports what a new line would inherit from an existing one,
// without changing anything.
//
// Asked before a line is created, because the answer is what somebody is
// agreeing to — and a carry that happened silently is the one nobody reviews.
func (s *Store) WouldCarry(ctx context.Context, subject access.Subject,
	fromTarget, toTarget int64) (*Carried, error) {

	if subject.Kind != access.Person {
		return nil, ErrNotTheirs
	}

	// productID is which product this is about, read from the build rather
	// than taken from the caller. The first version selected decisions by
	// live key and a matching place alone — and a place is a hash of
	// component names carrying no product, so a shared distribution
	// package matched across products and the reasoning of undisclosed
	// claims came back to anybody who could read one product.
	var productID int64
	if err := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("st.product_id").
		Where("tg.id = ?", toTarget).
		Scan(ctx, &productID); err != nil {
		return nil, fmt.Errorf("look up which product this line belongs to: %w", err)
	}
	if !mayDecide(subject, productID, access.Public) {
		return nil, ErrNotTheirs
	}
	readable := []access.Visibility{access.Public}
	if mayDecide(subject, productID, access.Private) {
		readable = append(readable, access.Private)
	}

	var rows []struct {
		DecisionID    int64  `bun:"decision_id"`
		Vulnerability string `bun:"vulnerability"`
		Component     string `bun:"component"`
		Outcome       string `bun:"outcome"`
		Was           string `bun:"was"`
		Now           string `bun:"now_at"`
		ConsumerWas   string `bun:"consumer_was"`
		ConsumerNow   string `bun:"consumer_now"`
		Reasoning     string `bun:"reasoning"`
		StillThere    bool   `bun:"still_there"`
		RanOut        bool   `bun:"ran_out"`
		// Carried so a postponement can be told how long it has already run.
		VulnerabilityID int64  `bun:"vulnerability_id"`
		PlaceIdentity   string `bun:"place_identity"`
	}
	err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = de.vulnerability_id`).
		// The argument, which is where the outcome lives.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		Join(`LEFT JOIN "claim_revision" AS "dr" ON dr.id = cl.revision_id`).
		ColumnExpr(`de.id AS "decision_id"`).
		ColumnExpr(`de.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`de.place_identity AS "place_identity"`).
		ColumnExpr(`v.identifier AS "vulnerability"`).
		ColumnExpr(`COALESCE(de.component_upstream_version, '') AS "was"`).
		ColumnExpr(`cl.outcome AS "outcome"`).
		ColumnExpr(`COALESCE(dr.body, '') AS "reasoning"`).
		// The new line's contents at that place, if anything.
		ColumnExpr(`COALESCE((SELECT MIN(c.name) FROM "finding" AS "f"
			JOIN "component" AS "c" ON c.id = f.component_id
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS "component"`, toTarget).
		// Both versions, because a decision is keyed on both. Comparing only
		// the component's meant a build whose *consumer* had moved was
		// reported as already covered, when the claim does not reach it and
		// the finding surfaces unanswered.
		ColumnExpr(`COALESCE((SELECT MIN(`+finding.ComponentUpstreamExpr+`) FROM "finding" AS "f"
			JOIN "component" AS "c" ON c.id = f.component_id
			LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS "now_at"`, toTarget).
		ColumnExpr(`COALESCE((SELECT MIN(`+finding.ConsumerUpstreamExpr+`) FROM "finding" AS "f"
			JOIN "component" AS "c" ON c.id = f.component_id
			LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS "consumer_now"`, toTarget).
		ColumnExpr(`COALESCE(de.consumer_upstream_version, '') AS "consumer_was"`).
		ColumnExpr(`EXISTS (SELECT 1 FROM "finding" AS "f"
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL)
			AS "still_there"`, toTarget).
		// A date it carries that has already gone by, either of them.
		ColumnExpr(`(COALESCE(cl.deferred_until, cl.committed_to) IS NOT NULL
			AND COALESCE(cl.deferred_until, cl.committed_to) <= ?) AS "ran_out"`, s.now()).
		Where("de.live_key IS NOT NULL").
		Where("de.product_id = ?", productID).
		Where("de.visibility IN (?)", bun.List(readable)).
		Where(`EXISTS (SELECT 1 FROM "finding" AS "g"
			WHERE g.target_id = ? AND g.vulnerability_id = de.vulnerability_id
			  AND g.place_identity = de.place_identity)`, fromTarget).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what a new line would inherit: %w", err)
	}

	carried := &Carried{}
	var postponed []at
	for _, row := range rows {
		if !row.StillThere {
			carried.Absent++
			continue
		}
		if row.Was == row.Now && row.ConsumerWas == row.ConsumerNow {
			// The versions match, so it reaches the new line by matching.
			// Offering it would ask somebody to agree to something that has
			// already happened.
			carried.Applying++
			continue
		}
		one := Inherited{
			DecisionID: row.DecisionID, Vulnerability: row.Vulnerability,
			Component: row.Component, Outcome: Outcome(row.Outcome),
			Was: row.Was, Now: row.Now, Reasoning: row.Reasoning,
		}
		// Anything the write would refuse is not offered. A carried judgment
		// keeps its date rather than having it quietly moved forward, so a
		// deferral that has already run out and a promise whose date has
		// gone by cannot be carried at all — and offering one is offering
		// something the act behind the button turns down.
		if row.RanOut {
			carried.Absent++
			continue
		}
		if Outcome(row.Outcome) == Deferred {
			postponed = append(postponed, at{row.VulnerabilityID, row.PlaceIdentity})
			carried.Postponed = append(carried.Postponed, one)
			continue
		}
		carried.Moved = append(carried.Moved, one)
	}

	// The length each postponement has already run. Somebody agreeing to carry
	// a deferral into a new line is agreeing to however long it has been put
	// off in total, not to the months the new one asks for — and four
	// consecutive carries of "not this release" are a decision nobody made.
	already, err := s.deferredSoFarAt(ctx, productID, postponed)
	if err != nil {
		return nil, err
	}
	for i := range carried.Postponed {
		carried.Postponed[i].DeferredDays = int(already[postponed[i]].Hours() / 24)
	}
	return carried, nil
}

// at is one place a decision was made about.
type at struct {
	vulnerability int64
	place         string
}

// deferredSoFarAt totals how long each of these places has been put off, in
// one statement rather than one per row.
//
// The arithmetic happens here rather than in SQL: subtracting one timestamp
// from another and summing the result has no portable spelling, and the rows
// are already being read.
func (s *Store) deferredSoFarAt(ctx context.Context, productID int64, places []at) (map[at]time.Duration, error) {
	total := map[at]time.Duration{}
	if len(places) == 0 {
		return total, nil
	}
	issues := make([]int64, 0, len(places))
	identities := make([]string, 0, len(places))
	wanted := make(map[at]bool, len(places))
	for _, place := range places {
		if wanted[place] {
			continue
		}
		wanted[place] = true
		issues = append(issues, place.vulnerability)
		identities = append(identities, place.place)
	}

	var deferrals []Decision
	if err := s.db.NewSelect().Model(&deferrals).Relation("Claim").
		Column("vulnerability_id", "place_identity", "proposed_at", "state", "ended_at").
		Where("de.product_id = ?", productID).
		Where("de.vulnerability_id IN (?)", bun.List(issues)).
		Where("de.place_identity IN (?)", bun.List(identities)).
		Where("claim.outcome = ?", Deferred).
		// Withdrawn ones for the span they were in force, as the threshold
		// counts them.
		Where("claim.deferred_until IS NOT NULL").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how long these have been put off: %w", err)
	}
	for _, deferral := range deferrals {
		key := at{deferral.VulnerabilityID, deferral.PlaceIdentity}
		// The pair of lists matches more combinations than were asked for, so
		// what was not asked for is dropped here.
		if !wanted[key] || deferral.Claim == nil || deferral.Claim.DeferredUntil == nil {
			continue
		}
		if span := heldFor(deferral); span > 0 {
			total[key] += span
		}
	}
	return total, nil
}

// ReaffirmingClaim is somebody saying every lapsed row of one action still
// holds.
type ReaffirmingClaim struct {
	// PreviousClaimID names the action whose rows stopped applying. The rows
	// are resolved here, for the reason a bulk judgment's places are: a caller
	// free to name them would be choosing which agreements get carried
	// forward.
	PreviousClaimID int64
	// Reasoning is the fresh reason, for all of them. One act is one argument,
	// which is what makes it one thing a second person can read.
	Reasoning string
	By        int64
	// Cap bounds a re-affirmed judgment, which this mostly is: the outcome
	// comes from the claim being re-made, so re-affirming a bulk dismissal
	// comes through here. A promise carries no bound, because the next scan
	// re-checks it; nothing re-checks a dismissal, which is the reason the cap
	// exists (REQ-27).
	Cap int
}

// Reaffirmed is what one bulk re-affirmation did.
type Reaffirmed struct {
	ClaimID int64
	// Decisions are the rows it wrote, and Places how many distinct places
	// they cover. A place at two versions in two builds is two rows, because
	// the versions are what a decision expires on.
	Decisions []int64
	Places    int
	// Waiting says a second person has to agree. One act, one approval: where
	// any row would need full approval, the whole of it does, because an
	// approver works at the unit the proposer acted at.
	Waiting bool
}

// ReaffirmClaim re-makes every lapsed row of one action, in one act.
//
// Bulk at the same three grains deciding has. A team answering one kernel
// issue writes a decision at each of its 45 places in one action; when the
// kernel moves, those 45 lapse, and restoring them one at a time is 45
// requests with 45 separately typed justifications. This is the one path that
// is safe to make cheap: a version bump is a prompt to re-check rather than a
// new claim, and the earlier agreement is already carried forward.
//
// It also breaks nothing REQ-28 asks for: approval, send-back and undo operate
// on the claim, and this brings re-affirmation to the same grain.
//
// Every escalation rule the single form applies is applied here, per row, and
// any one of them puts the whole act through full approval. An act whose rows
// were approved separately would be an approver agreeing to part of an argument
// they were shown whole.
func (s *Store) ReaffirmClaim(ctx context.Context, subject access.Subject,
	r ReaffirmingClaim) (Reaffirmed, error) {

	if r.By != subject.ID {
		return Reaffirmed{}, fmt.Errorf("a decision is recorded as made by whoever made it")
	}
	var out Reaffirmed
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		out = Reaffirmed{}
		made, err := within.reaffirmClaim(ctx, subject, r)
		if err != nil {
			return err
		}
		out = made
		return nil
	})
	return out, err
}

// reaffirmClaim is the whole of it, in the transaction that writes.
//
// Everything it turns on is read in here: which rows lapsed, where they sit
// now, how bad each issue is judged to be today, and whether there is an
// agreement to carry. Read outside, every one of them is an answer about a
// database that has since moved.
func (s *Store) reaffirmClaim(ctx context.Context, subject access.Subject,
	r ReaffirmingClaim) (Reaffirmed, error) {

	previous := new(Claim)
	if err := s.db.NewSelect().Model(previous).
		Where("id = ?", r.PreviousClaimID).Scan(ctx); err != nil {
		return Reaffirmed{}, ErrNotTheirs
	}
	var lapsed []Decision
	if err := s.db.NewSelect().Model(&lapsed).
		Where("de.claim_id = ?", r.PreviousClaimID).
		Where("de.state = ?", LapsedState).
		Order("de.id ASC").Scan(ctx); err != nil {
		return Reaffirmed{}, fmt.Errorf("read what lapsed under that claim: %w", err)
	}
	// Authorized against the rows before anything else is said about the
	// claim, and asked of every one, because a claim covering a disclosed
	// place and an undisclosed one is not one a public triager may re-make in
	// part.
	//
	// Before the proposer check, not after (REQ-42). Refusing on the
	// proposer first answered a claim in a product the caller cannot see
	// differently from one that does not exist — one sentence against a bare
	// refusal — which turns walking claim identifiers into a directory of
	// every product in the deployment.
	for _, row := range lapsed {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return Reaffirmed{}, ErrNotTheirs
		}
	}
	if len(lapsed) == 0 {
		return Reaffirmed{}, ErrNotTheirs
	}
	// The same rule the single form applies, asked once because a claim has
	// one proposer. Without it an approver could re-affirm, becoming proposer
	// of the new claim while their own earlier agreement is carried onto it.
	if previous.ProposedBy != subject.ID {
		return Reaffirmed{}, fmt.Errorf(
			"only the person who made a decision may re-affirm it; anybody else proposes it afresh")
	}

	where, err := s.whereTheyAreNow(ctx, subject, lapsed)
	if err != nil {
		return Reaffirmed{}, err
	}

	// The need for a second person, decided over the whole act before
	// any of it is written. Any row escalating carries the rest with it: an
	// approver works at the unit the proposer acted at, and splitting the act
	// would be agreeing to part of an argument they were shown whole.
	carryable, err := s.approvalToCarry(ctx, r.PreviousClaimID, subject.ID)
	if err != nil {
		return Reaffirmed{}, err
	}
	severity := map[[2]int64]int{}
	full := false
	for _, row := range lapsed {
		key := [2]int64{row.ProductID, row.VulnerabilityID}
		if _, asked := severity[key]; !asked {
			now, err := s.severityOf(ctx, row.ProductID, row.VulnerabilityID)
			if err != nil {
				return Reaffirmed{}, err
			}
			severity[key] = now
		}
		if needsFullApproval(row, severity[key], carryable != nil) {
			full = true
		}
	}

	justification, mitigation, fixedVersion := "", "", ""
	if previous.Justification != nil {
		justification = *previous.Justification
	}
	if previous.Mitigation != nil {
		mitigation = *previous.Mitigation
	}
	if previous.FixedVersion != nil {
		fixedVersion = *previous.FixedVersion
	}

	proposals := make([]Proposal, 0, len(lapsed))
	places := map[string]bool{}
	// One place, however many rows of the claim lapsed at it. A place identity
	// is names alone while a decision is keyed on the versions too, so one
	// component at two versions under one consumer is two lapsed rows sharing
	// a place — and walking both would resolve the same current place twice,
	// write the same live key twice, and refuse the whole act with "a decision
	// already stands here", which is false.
	done := map[string]bool{}
	for _, row := range lapsed {
		key := placeKey(row.ProductID, row.VulnerabilityID, row.PlaceIdentity)
		if done[key] {
			continue
		}
		done[key] = true
		for _, at := range where[key] {
			// The visibility it had. A re-affirmation says the same claim
			// still holds; it is not an occasion to change who may see it.
			at.Visibility = row.Visibility
			places[row.PlaceIdentity] = true
			proposals = append(proposals, Proposal{
				Place: at, Outcome: previous.Outcome,
				Justification: Justification(justification),
				Mitigation:    mitigation,
				DeferredUntil: previous.DeferredUntil,
				FixedVersion:  fixedVersion,
				Reasoning:     r.Reasoning, By: r.By,
				SeverityCenti: severity[[2]int64{row.ProductID, row.VulnerabilityID}],
				NeedsApproval: full,
			})
		}
	}
	if len(proposals) == 0 {
		return Reaffirmed{}, fmt.Errorf(
			"%w: none of what lapsed is open anywhere any more", ErrNothingOpen)
	}
	// Bounded unless it is a promise. What decides is the outcome being
	// re-made rather than the act being a re-affirmation: this path carries
	// the previous claim's outcome, so a lapsed bulk dismissal re-made here is
	// a bulk judgment and nothing re-checks it. Unbounded it would write as
	// many rows as it liked, and with the earlier agreement carried on, nobody
	// would stand between the request and the rows.
	if previous.Outcome == UpgradeNeeded {
		if err := permitted(subject, proposals, s.now()); err != nil {
			return Reaffirmed{}, err
		}
	} else if err := allowed(subject, proposals, r.Cap, s.now()); err != nil {
		return Reaffirmed{}, err
	}

	// One act, one claim, one argument — the shape every other bulk write
	// here takes.
	claim, err := s.newClaim(ctx, FindingClaim, r.By, &r.PreviousClaimID, "", proposals[0])
	if err != nil {
		return Reaffirmed{}, err
	}
	written, err := s.proposeAll(ctx, claim, proposals)
	if err != nil {
		return Reaffirmed{}, err
	}
	out := Reaffirmed{ClaimID: claim.ID, Places: len(places), Waiting: full}
	for _, one := range written {
		out.Decisions = append(out.Decisions, one.ID)
	}
	if full {
		return out, nil
	}
	// Carried once, onto the claim, because an approval is an agreement to one
	// claim's words. Written per row it would be one agreement recorded forty
	// five times.
	if err := s.carryApprovalTo(ctx, written, *claim, lapsed[0]); err != nil {
		return Reaffirmed{}, err
	}
	return out, nil
}

// placeKey identifies a lapsed row's place within its product.
func placeKey(productID, vulnerabilityID int64, placeIdentity string) string {
	return fmt.Sprintf("%d\x00%d\x00%s", productID, vulnerabilityID, placeIdentity)
}

// whereTheyAreNow is the versions each lapsed place sits at today, which is
// what the re-made decisions expire on.
//
// Narrowed by the two lists rather than by the pairs. No engine here spells
// a comparison against a pair of columns the same way, so the statement asks
// for the issues and the places separately — a superset — and the pairing is
// done on the way back.
//
// A place at two versions in two builds comes back twice, and is two decisions:
// the versions are what a decision expires on, so one row could not stand for
// both. A place that is open nowhere comes back not at all, which is a finding
// that closed rather than a fault.
func (s *Store) whereTheyAreNow(ctx context.Context, subject access.Subject,
	lapsed []Decision) (map[string][]Place, error) {

	issues := map[int64]bool{}
	identities := map[string]bool{}
	products := map[int64]bool{}
	for _, row := range lapsed {
		issues[row.VulnerabilityID] = true
		identities[row.PlaceIdentity] = true
		products[row.ProductID] = true
	}
	at := map[string][]Place{}
	for productID := range products {
		visible := access.Visible(subject, productID)
		if len(visible) == 0 {
			return nil, ErrNotTheirs
		}
		var rows []struct {
			VulnerabilityID   int64  `bun:"vulnerability_id"`
			PlaceIdentity     string `bun:"place_identity"`
			ComponentUpstream string `bun:"component_upstream"`
			ConsumerUpstream  string `bun:"consumer_upstream"`
			OnTag             int    `bun:"on_tag"`
		}
		err := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
			ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
			ColumnExpr(`f.place_identity AS "place_identity"`).
			ColumnExpr(finding.ComponentUpstreamExpr+` AS "component_upstream"`).
			ColumnExpr(finding.ConsumerUpstreamExpr+` AS "consumer_upstream"`).
			ColumnExpr(`MAX(CASE WHEN st.kind = ? THEN 1 ELSE 0 END) AS "on_tag"`, catalog.Tag).
			Where("st.product_id = ?", productID).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible)).
			Where("f.vulnerability_id IN (?)", bun.List(keysOf(issues))).
			Where("f.place_identity IN (?)", bun.List(wordsOf(identities))).
			GroupExpr("f.vulnerability_id, f.place_identity, c.upstream_version, c.version, "+
				"uc.upstream_version, uc.version").
			Scan(ctx, &rows)
		if err != nil {
			return nil, fmt.Errorf("read where these sit now: %w", err)
		}
		for _, row := range rows {
			key := placeKey(productID, row.VulnerabilityID, row.PlaceIdentity)
			at[key] = append(at[key], Place{
				ProductID: productID, VulnerabilityID: row.VulnerabilityID,
				PlaceIdentity:     row.PlaceIdentity,
				ComponentUpstream: row.ComponentUpstream,
				ConsumerUpstream:  row.ConsumerUpstream,
				OnTag:             row.OnTag == 1,
			})
		}
	}
	return at, nil
}

// keysOf and wordsOf are a set as a list, for binding into a statement.
func keysOf(set map[int64]bool) []int64 {
	out := make([]int64, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	return out
}

func wordsOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for word := range set {
		out = append(out, word)
	}
	return out
}
