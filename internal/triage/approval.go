package triage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// Approve records a second person agreeing to what a decision currently says.
//
// Against one revision, not against the decision. The whole value of a second
// pair of eyes is that they read particular words; an approval that floats
// free of the words would still be standing after somebody rewrote them, and
// nothing would report that.
//
// The proposer may never be the approver, with no override. A one-person
// deployment therefore cannot approve anything, which is the control working
// rather than a gap in it — and it is better said plainly than quietly
// relaxed.
// Revise states the reasoning again, and takes back any approval standing on
// what it said before.
//
// Withdrawing the approval is the point rather than a side effect. A second
// person agreed to particular words; different words are a claim nobody has
// agreed to, and letting the approval carry over would defeat the control
// silently — which is worse than not having it, because the record would say
// two people had read something only one of them had.
//
// It needs no approval of its own. Returning something to the queue re-exposes
// risk rather than hiding it, and the queue exists to stop risk being hidden
// unseen.
func (s *Store) Revise(ctx context.Context, subject access.Subject, claimID int64, reasoning string) (*Revision, error) {
	db, ok := database.Handle(s.db)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}

	var written *Revision
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		var err error
		written, err = within.revise(ctx, subject, claimID, reasoning)
		return err
	})
	return written, err
}

// revise is the whole of a revision, inside a transaction the caller opened.
//
// **The policy is checked here rather than by each caller.** Every path that
// stores typed text runs it before the text is stored, so that what is in the
// column is known to have passed what was in force when it arrived — and a
// second entry point that reached the write without it stored raw HTML,
// remote images and text past the bound a render is kept inside.
func (s *Store) revise(ctx context.Context, subject access.Subject, claimID int64,
	reasoning string) (*Revision, error) {

	if strings.TrimSpace(reasoning) == "" {
		return nil, errors.New("a revision has to say something")
	}
	if err := markdown.Check(reasoning); err != nil {
		return nil, err
	}

	claim, rows, err := s.claimRows(ctx, subject, claimID, mayDecide)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return nil, ErrNotTheirs
		}
	}

	var latest int64
	if err := s.db.NewSelect().Model((*Revision)(nil)).
		ColumnExpr("COALESCE(MAX(ordinal), 0)").
		Where("claim_id = ?", claimID).Scan(ctx, &latest); err != nil {
		return nil, fmt.Errorf("read what has been said already: %w", err)
	}
	if latest == 0 {
		return nil, ErrNotTheirs
	}

	now := s.now().Truncate(time.Microsecond)
	revision := &Revision{
		ClaimID: claimID, Ordinal: latest + 1,
		Body: reasoning, WrittenBy: subject.ID, WrittenAt: now,
	}
	if _, err := s.db.NewInsert().Model(revision).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record a revision: %w", err)
	}
	if err := noting(ctx, s.db, reasoning, revision.WrittenAt); err != nil {
		return nil, err
	}

	// Every approval standing on the old words is taken back, and the claim
	// goes back to being a proposal. It is marked as having been approved
	// before — an approver meeting it again should know they are re-reading
	// something rather than seeing it for the first time — which is what the
	// kept approval rows say.
	//
	// **Whole, because the argument is whole.** Per row, revising one of
	// forty-four returned that row to the queue and left the other forty-three
	// saying the old thing under a claim that read as agreed.
	if _, err := s.db.NewUpdate().Model((*Approval)(nil)).
		Set("withdrawn_at = ?", now).
		Where("claim_id = ?", claimID).
		Where("withdrawn_at IS NULL").Exec(ctx); err != nil {
		return nil, fmt.Errorf("withdraw the approvals on what was revised: %w", err)
	}
	if _, err := s.db.NewUpdate().Model((*Claim)(nil)).
		Set("revision_id = ?", revision.ID).
		Where("id = ?", claimID).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record a revision: %w", err)
	}
	claim.RevisionID = &revision.ID

	for _, row := range rows {
		// Retaken, because revising a withdrawn or lapsed claim brings it back
		// to life and the key is what the uniqueness rule is enforced through.
		// Without this the row is live and holds nothing, the unique index
		// cannot see it, and a second contradictory claim about the same code
		// is accepted — both can then be approved, with one silently
		// governing. That is the exact failure the rule exists to prevent,
		// walked around rather than raced.
		key := liveKeyFor(Place{
			ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
			PlaceIdentity:     row.PlaceIdentity,
			ComponentUpstream: orEmpty(row.ComponentUpstreamVersion),
			ConsumerUpstream:  orEmpty(row.ConsumerUpstreamVersion),
		})
		if _, err := s.db.NewUpdate().Model((*Decision)(nil)).
			Set("state = ?", Proposed).
			Set("live_key = ?", key).
			// Whatever was asked for has been answered, or at least responded
			// to. Leaving the mark would keep the claim out of the approval
			// queue forever, which is the failure that makes sending back
			// unusable.
			Set("sent_back_at = ?", nil).
			Where("id = ?", row.ID).Exec(ctx); err != nil {
			return nil, fmt.Errorf("record a revision: %w", err)
		}
	}
	return revision, nil
}

// Withdraw takes a claim back.
//
// Whole, because an argument is whole: withdrawing part of one is setting rows
// aside, which is a different act with a different record.
//
// No approval needed, for the same reason revising needs none: it puts risk
// back on the table rather than taking it off.
func (s *Store) Withdraw(ctx context.Context, subject access.Subject, claimID int64) error {
	db, ok := database.Handle(s.db)
	if !ok {
		return fmt.Errorf("this store is already inside a transaction")
	}
	// Both writes or neither. Half of this leaves a claim reading as agreed to
	// with every agreement marked withdrawn — which is the state the whole
	// approval record exists to make impossible.
	return database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		_, rows, err := within.claimRows(ctx, subject, claimID, mayDecide)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
				return ErrNotTheirs
			}
		}
		now := s.now().Truncate(time.Microsecond)
		if _, err := tx.NewUpdate().Model((*Approval)(nil)).
			Set("withdrawn_at = ?", now).
			Where("claim_id = ?", claimID).
			Where("withdrawn_at IS NULL").Exec(ctx); err != nil {
			return fmt.Errorf("withdraw a claim: %w", err)
		}
		if _, err := tx.NewUpdate().Model((*Decision)(nil)).
			Set("state = ?", Withdrawn).
			Set("ended_at = ?", now).
			// Released, so the places are open to a fresh claim. A withdrawn
			// claim is history, and history must not stop anybody deciding.
			Set("live_key = ?", nil).
			Where("claim_id = ?", claimID).Exec(ctx); err != nil {
			return fmt.Errorf("withdraw a claim: %w", err)
		}
		return nil
	})
}

// UndoBatch takes back everything one bulk approval agreed to.
//
// A reviewer may approve a long selection in one action, so undoing has to be
// available at the same size. Hunting for what a bulk approval touched, one
// row at a time, is not an undo anybody will actually use.
func (s *Store) UndoBatch(ctx context.Context, subject access.Subject, batch string) (Undone, error) {
	db, ok := database.Handle(s.db)
	if !ok {
		return Undone{}, fmt.Errorf("this store is already inside a transaction")
	}
	var undone Undone
	// Applied whole, and every read it decides from is inside it. Reading
	// which decisions a batch covered and then writing outside that read lets
	// a decision withdrawn in between be flipped back to waiting.
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		var err error
		undone, err = (&Store{db: tx, now: s.now}).undoBatch(ctx, subject, batch)
		return err
	})
	return undone, err
}

// Undone is what taking a bulk approval back did, and who is waiting to hear
// about it.
//
// An undo is one of the two outcomes a proposer is told about, because it is
// the one nobody expects: it reverses something they were relying on, and
// everything else that happens to a claim is either what they asked for or
// something they did themselves.
type Undone struct {
	// Rows is how many decisions returned to waiting.
	Rows int64
	// Told is who to tell, once each.
	Told []ForPerson
}

// ForPerson is somebody with something to hear, and enough to say it with: a
// representative row to link to, how many rows are theirs, and whether any of
// them is about a finding nobody has announced — which is what decides what
// may leave this deployment.
//
// Read off the rows rather than off a representative. A claim is one action
// over many places whose rows need not agree about visibility, so the earliest
// row being public says nothing about the rest.
type ForPerson struct {
	PersonID   int64
	DecisionID int64
	// ProductID is the product the representative decision is in, which is
	// what a telling about these rows is narrowed by later. A person's set
	// may span products; the representative names one of them, the same way
	// DecisionID does.
	ProductID       int64
	VulnerabilityID int64
	Rows            int
	Undisclosed     bool
}

func (s *Store) undoBatch(ctx context.Context, subject access.Subject, batch string) (Undone, error) {
	now := s.now().Truncate(time.Microsecond)

	// Narrowed to what this person may reach before anything is undone. A
	// batch is one reviewer's afternoon and may span products, so undoing it
	// wholesale would let somebody act on products they hold nothing on.
	var decisions []int64
	covered := s.db.NewSelect().Model((*Approval)(nil)).
		ColumnExpr("d.id").
		Join(`JOIN "decision" AS "d" ON d.claim_id = da.claim_id`).
		Where("da.batch = ?", batch).Where("da.withdrawn_at IS NULL")
	covered = approvableBy(covered, subject, "d")
	if err := covered.Scan(ctx, &decisions); err != nil {
		return Undone{}, fmt.Errorf("read what that approval covered: %w", err)
	}
	if len(decisions) == 0 {
		return Undone{}, nil
	}

	// Who proposed them, read inside the same transaction as the writes
	// that follow and before them, because what is being reported is who
	// wrote the claims this batch agreed to — which is a fact about the
	// rows that the undo does not change.
	told, err := s.proposersOf(ctx, decisions)
	if err != nil {
		return Undone{}, err
	}

	if _, err := s.db.NewUpdate().Model((*Approval)(nil)).
		Set("withdrawn_at = ?", now).
		Where("batch = ?", batch).Where("withdrawn_at IS NULL").
		Where(`claim_id IN (SELECT claim_id FROM "decision" WHERE id IN (?))`,
			bun.List(decisions)).Exec(ctx); err != nil {
		return Undone{}, fmt.Errorf("undo an approval: %w", err)
	}
	// Back to proposed rather than withdrawn: the claims still stand, it is
	// the agreement to them that was taken back.
	//
	// Only where nothing else still agrees. A decision may carry more than one
	// agreement, and undoing a batch is undoing that batch — sending a
	// decision back to the queue while somebody's standing agreement to it is
	// still recorded would discard an agreement nobody took back.
	if _, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set("state = ?", Proposed).
		// Cleared here as well as on a revision. A claim sent back and then
		// approved under a batch, with the batch later undone, was left
		// proposed, needing approval, and in no queue at all — visible to
		// nobody but whoever knew its identifier.
		Set("sent_back_at = ?", nil).
		Where("id IN (?)", bun.List(decisions)).
		Where(`NOT EXISTS (SELECT 1 FROM "claim_approval" AS "still" ` +
			"WHERE still.claim_id = de.claim_id AND still.withdrawn_at IS NULL)").
		Exec(ctx); err != nil {
		return Undone{}, fmt.Errorf("undo an approval: %w", err)
	}
	return Undone{Rows: int64(len(decisions)), Told: told}, nil
}

// proposersOf gathers who wrote a set of decisions, one entry each.
func (s *Store) proposersOf(ctx context.Context, ids []int64) ([]ForPerson, error) {
	var rows []Decision
	if err := s.db.NewSelect().Model(&rows).
		Column("id", "proposed_by", "visibility", "product_id", "vulnerability_id").
		Where("id IN (?)", bun.List(ids)).Order("id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who proposed these: %w", err)
	}
	at := map[int64]int{}
	told := make([]ForPerson, 0, 4)
	for _, row := range rows {
		i, seen := at[row.ProposedBy]
		if !seen {
			at[row.ProposedBy] = len(told)
			told = append(told, ForPerson{
				PersonID: row.ProposedBy, DecisionID: row.ID,
				ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
			})
			i = len(told) - 1
		}
		told[i].Rows++
		if row.Visibility == access.Private {
			told[i].Undisclosed = true
		}
	}
	return told, nil
}

// authorOf returns who wrote the reasoning a claim currently rests on.
func (s *Store) authorOf(ctx context.Context, claim Claim) (int64, error) {
	if claim.RevisionID == nil {
		return 0, ErrNothingToApprove
	}
	revision := new(Revision)
	if err := s.db.NewSelect().Model(revision).
		Where("id = ?", *claim.RevisionID).Scan(ctx); err != nil {
		return 0, fmt.Errorf("read who wrote this: %w", err)
	}
	return revision.WrittenBy, nil
}

// covering counts the open findings a claim covers right now.
//
// The same match a finding makes when it asks whether a decision applies to
// it: the place, and both upstream versions. Read at the moment of approval
// and kept, because a claim reaches by matching and so covers more as builds
// appear — with nobody having acted, and nobody having agreed to the larger
// number.
//
// One statement over every row of the claim, whatever its size. A claim over a
// kernel is two thousand rows, and a count per row was a count per round trip.
func (s *Store) covering(ctx context.Context, subject access.Subject, ids []int64) (int, error) {
	// Narrowed like every other count here. What is stored on the approval is
	// served back, so an unnarrowed count discloses how many undisclosed
	// findings sit behind a claim to somebody who may not read one.
	readable := readableVisibilities(subject, ids, s, ctx)
	covered, err := s.db.NewSelect().
		TableExpr(`"decision" AS "de"`).
		Join(`JOIN "finding" AS "f" ON f.vulnerability_id = de.vulnerability_id`+
			" AND f.place_identity = de.place_identity").
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id AND st.product_id = de.product_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		Where("de.id IN (?)", bun.List(ids)).
		Where("f.closed_at IS NULL").
		Where("COALESCE(de.component_upstream_version, '') = "+finding.ComponentUpstreamExpr).
		Where("COALESCE(de.consumer_upstream_version, '') = "+finding.ConsumerUpstreamExpr).
		Where("f.visibility IN (?)", bun.List(readable)).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count what this covers: %w", err)
	}
	return covered, nil
}
