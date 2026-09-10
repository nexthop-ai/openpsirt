package triage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
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
func (s *Store) Reaffirm(ctx context.Context, subject access.Subject, r Reaffirmation, severityNow int) (*Decision, error) {
	if !mayDecideOn(subject, r.Place.ProductID, r.Place.VulnerabilityID, visibilityOf(r.Place)) {
		return nil, ErrNotTheirs
	}
	if r.By != subject.ID {
		return nil, fmt.Errorf("a decision is recorded as made by whoever made it")
	}

	db, ok := s.db.(*bun.DB)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}

	var made *Decision
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		var err error
		made, err = (&Store{db: tx, now: s.now}).reaffirm(ctx, subject, r, severityNow)
		return err
	})
	if errors.Is(err, ErrAlreadyDecided) {
		// Read now the transaction has unwound, so the refusal can say which
		// claim to go and read rather than which constraint was violated.
		if standing, found := s.liveAt(ctx, liveKeyFor(r.Place)); found {
			return nil, fmt.Errorf(
				"%w: decision %d is already %s here — revise that one rather than recording a "+
					"second claim about the same code",
				ErrAlreadyDecided, standing.ID, standing.State)
		}
	}
	if err != nil {
		return nil, err
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
func (s *Store) reaffirm(ctx context.Context, subject access.Subject, r Reaffirmation,
	severityNow int) (*Decision, error) {

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

	// Whether this needs a second person is decided before it is written, and
	// recorded on the claim. Without it the claim was stored as needing
	// nobody — so a re-affirmation sent back for full approval suppressed the
	// finding the moment it was made and never appeared in the review queue,
	// which is one person's action producing a live dismissal no second person
	// ever sees.
	// Whether there is an agreement to carry at all, asked of the approvals
	// rather than inferred from the state. A claim lapses from Proposed as
	// well as from Approved (the code moved out from under it either way), so
	// "it lapsed" says nothing about whether anybody ever agreed to it.
	carryable, err := s.approvalToCarry(ctx, previous.ClaimID, subject.ID)
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
	// The concrete path this refuses: propose, have it agreed to, revise
	// (which withdraws the agreement), let a version bump lapse it, re-affirm.
	earlier, err := s.approvalToCarry(ctx, previous.ClaimID, made.ProposedBy)
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
	result, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set("state = ?", Approved).
		Where("id = ?", made.ID).
		Where(`EXISTS (SELECT 1 FROM "claim" AS ac WHERE ac.id = ? AND ac.revision_id = ?)`,
			claim.ID, *claim.RevisionID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("carry an approval forward: %w", err)
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("carry an approval forward: %w", err)
	}
	if changed == 0 {
		return fmt.Errorf("the reasoning changed while this was being agreed to")
	}
	made.State = Approved
	return nil
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
// **A decision covering nothing in the product is not lapsed.** A component
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
type Lapsed struct {
	// Rows is how many decisions stopped applying.
	Rows int64
	// Told is who to tell, once each.
	Told []ForPerson
}

func (s *Store) Lapse(ctx context.Context, targetID int64) (Lapsed, error) {
	// Every open finding of this target at the decision's place, with the
	// versions it currently has — stated the same way the decision was written
	// against them, from the same expression, so that a decision cannot lapse
	// on one path and stand on the other.
	openHere := func() *bun.SelectQuery {
		return s.db.NewSelect().
			ColumnExpr("1").
			TableExpr("finding AS f").
			Join("JOIN component AS c ON c.id = f.component_id").
			Join("LEFT JOIN component AS uc ON uc.id = f.consumer_id").
			Where("f.target_id = ?", targetID).
			Where("f.closed_at IS NULL").
			Where("f.vulnerability_id = de.vulnerability_id").
			Where("f.place_identity = de.place_identity")
	}
	matching := "COALESCE(de.component_upstream_version, '') = " + finding.ComponentUpstreamExpr +
		" AND COALESCE(de.consumer_upstream_version, '') = " + finding.ConsumerUpstreamExpr

	// Any open finding in the decision's product, in any build, still at the
	// versions it was decided about.
	stillCovered := s.db.NewSelect().
		ColumnExpr("1").
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("LEFT JOIN component AS uc ON uc.id = f.consumer_id").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Where("st.product_id = de.product_id").
		Where("f.closed_at IS NULL").
		Where("f.vulnerability_id = de.vulnerability_id").
		Where("f.place_identity = de.place_identity").
		Where(matching)

	// Still found here, at versions that are not the ones this was decided
	// about, and no longer found at those versions anywhere in the product.
	// Absent and empty are the same answer on the finding's side, so a
	// decision recorded against no version matches a component stating none.
	moment := s.now().Truncate(time.Microsecond)
	result, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set("state = ?", LapsedState).
		Set("ended_at = ?", moment).
		// Released for the same reason a withdrawal is: the code moved out
		// from under this, so it covers nothing, and somebody has to be able
		// to decide about what is there now.
		Set("live_key = ?", nil).
		Where("state IN (?, ?)", Proposed, Approved).
		Where("de.product_id = (?)", s.db.NewSelect().
			ColumnExpr("st.product_id").
			TableExpr("target AS tg").
			Join("JOIN stream AS st ON st.id = tg.stream_id").
			Where("tg.id = ?", targetID)).
		Where("EXISTS (?)", openHere().Where("NOT ("+matching+")")).
		Where("NOT EXISTS (?)", stillCovered).
		Exec(ctx)
	if err != nil {
		return Lapsed{}, fmt.Errorf("mark what the code moved out from under: %w", err)
	}
	moved, err := result.RowsAffected()
	if err != nil {
		// Not every driver reports it. The rows are marked either way, and
		// what follows reads them back rather than trusting this number.
		moved = 0
	}

	// Who to tell, read back by the moment just written rather than by
	// collecting identifiers first. A sweep over a real image can lapse
	// thousands of rows at once, and an update naming every one of them in an
	// IN list is a statement whose size is the estate's.
	//
	// The moment is this pass's own, truncated to the microsecond, and the
	// product is this target's — so two sweeps running at once cannot read
	// each other's rows even if their clocks agree.
	var lapsed []int64
	if err := s.db.NewSelect().Model((*Decision)(nil)).
		ColumnExpr("de.id").
		Where("de.state = ?", LapsedState).
		Where("de.ended_at = ?", moment).
		Where("de.product_id = (?)", s.db.NewSelect().
			ColumnExpr("st.product_id").
			TableExpr("target AS tg").
			Join("JOIN stream AS st ON st.id = tg.stream_id").
			Where("tg.id = ?", targetID)).
		Scan(ctx, &lapsed); err != nil {
		return Lapsed{}, fmt.Errorf("read what lapsed: %w", err)
	}
	if len(lapsed) == 0 {
		return Lapsed{Rows: moved}, nil
	}
	told, err := s.proposersOf(ctx, lapsed)
	if err != nil {
		return Lapsed{}, err
	}
	if moved == 0 {
		moved = int64(len(lapsed))
	}
	return Lapsed{Rows: moved, Told: told}, nil
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

	// Which product this is about, read from the build rather than taken from
	// the caller. The first version selected decisions by live key and a
	// matching place alone — and a place is a hash of component names carrying
	// no product, so a shared distribution package matched across products and
	// the reasoning of undisclosed claims came back to anybody who could read
	// one product.
	var productID int64
	if err := s.db.NewSelect().
		TableExpr("target AS tg").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
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
		TableExpr("decision AS de").
		Join("JOIN vulnerability AS v ON v.id = de.vulnerability_id").
		// The argument, which is where the outcome lives.
		Join("JOIN claim AS cl ON cl.id = de.claim_id").
		Join("LEFT JOIN claim_revision AS dr ON dr.id = cl.revision_id").
		ColumnExpr("de.id AS decision_id").
		ColumnExpr("de.vulnerability_id AS vulnerability_id").
		ColumnExpr("de.place_identity AS place_identity").
		ColumnExpr("v.identifier AS vulnerability").
		ColumnExpr("COALESCE(de.component_upstream_version, '') AS was").
		ColumnExpr("cl.outcome AS outcome").
		ColumnExpr("COALESCE(dr.body, '') AS reasoning").
		// What the new line has at that place, if anything.
		ColumnExpr(`COALESCE((SELECT MIN(c.name) FROM "finding" AS f
			JOIN "component" AS c ON c.id = f.component_id
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS component`, toTarget).
		// Both versions, because a decision is keyed on both. Comparing only
		// the component's meant a build whose *consumer* had moved was
		// reported as already covered, when the claim does not reach it and
		// the finding surfaces unanswered.
		ColumnExpr(`COALESCE((SELECT MIN(`+finding.ComponentUpstreamExpr+`) FROM "finding" AS f
			JOIN "component" AS c ON c.id = f.component_id
			LEFT JOIN "component" AS uc ON uc.id = f.consumer_id
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS now_at`, toTarget).
		ColumnExpr(`COALESCE((SELECT MIN(`+finding.ConsumerUpstreamExpr+`) FROM "finding" AS f
			JOIN "component" AS c ON c.id = f.component_id
			LEFT JOIN "component" AS uc ON uc.id = f.consumer_id
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL), '')
			AS consumer_now`, toTarget).
		ColumnExpr("COALESCE(de.consumer_upstream_version, '') AS consumer_was").
		ColumnExpr(`EXISTS (SELECT 1 FROM "finding" AS f
			WHERE f.target_id = ? AND f.vulnerability_id = de.vulnerability_id
			  AND f.place_identity = de.place_identity AND f.closed_at IS NULL)
			AS still_there`, toTarget).
		// Whether the date it carries has already gone by, either date.
		ColumnExpr(`(COALESCE(cl.deferred_until, cl.committed_to) IS NOT NULL
			AND COALESCE(cl.deferred_until, cl.committed_to) <= ?) AS ran_out`, s.now()).
		Where("de.live_key IS NOT NULL").
		Where("de.product_id = ?", productID).
		Where("de.visibility IN (?)", bun.List(readable)).
		Where(`EXISTS (SELECT 1 FROM "finding" AS g
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
		// What the write would refuse is not offered. A carried judgment
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

	// How long each postponement has already run. Somebody agreeing to carry
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
