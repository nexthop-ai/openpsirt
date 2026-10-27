// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Revise states the reasoning again, and takes back any approval standing on
// what it said before.
//
// Withdrawing the approval is the point rather than a side effect. A second
// person agreed to particular words; different words are a decision nobody has
// agreed to, and letting the approval carry over would defeat the control
// silently — which is worse than not having it, because the record would say
// two people had read something only one of them had.
//
// It needs no approval of its own. Returning something to the queue re-exposes
// risk rather than hiding it, and the queue exists to stop risk being hidden
// unseen.
func (s *Store) Revise(ctx context.Context, subject access.Subject, decisionID int64, reasoning string) (Revised, error) {
	var written Revised
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		var err error
		written, err = within.revise(ctx, subject, decisionID, reasoning)
		return err
	})
	var taken *occurrenceTaken
	if errors.As(err, &taken) {
		return written, s.alreadyDecided(ctx, ErrAlreadyDecided, taken.occurrences)
	}
	return written, err
}

// occurrenceTaken is a revision refused because another decision now stands at one of
// the occurrences the revised decision would retake, with the occurrences to name it from.
// The standing decision is read once the transaction has unwound, as every
// refusal naming one is.
type occurrenceTaken struct{ occurrences []Occurrence }

func (e *occurrenceTaken) Error() string { return ErrAlreadyDecided.Error() }
func (e *occurrenceTaken) Unwrap() error { return ErrAlreadyDecided }

// Revised is a revision, and the people whose agreement it took back.
type Revised struct {
	Revision *Revision
	// Withdrawn is everybody whose standing agreement the revision withdrew,
	// once each, leaving out whoever revised it. An agreement that stops
	// counting with nobody told is one its giver goes on relying on.
	Withdrawn []ForPerson
}

// revise is the whole of a revision, inside a transaction the caller opened.
//
// The policy is checked here rather than by each caller. Every path that
// stores typed text runs it before the text is stored, so that what is in the
// column is known to have passed what was in force when it arrived — and a
// second entry point that reached the write without it stored raw HTML,
// remote images and text past the bound a render is kept inside.
func (s *Store) revise(ctx context.Context, subject access.Subject, decisionID int64,
	reasoning string) (Revised, error) {

	if strings.TrimSpace(reasoning) == "" {
		return Revised{}, refusal.New("a revision has to say something")
	}
	if err := markdown.Check(reasoning); err != nil {
		return Revised{}, err
	}

	decision, rows, err := s.writableRows(ctx, subject, decisionID, mayDecideOn)
	if err != nil {
		return Revised{}, err
	}
	for _, row := range rows {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return Revised{}, ErrNotTheirs
		}
	}

	var latest int64
	if err := s.db.NewSelect().Model((*Revision)(nil)).
		ColumnExpr(`COALESCE(MAX("ordinal"), 0)`).
		Where(`"decision_id" = ?`, decisionID).Scan(ctx, &latest); err != nil {
		return Revised{}, fmt.Errorf("read what has been said already: %w", err)
	}
	if latest == 0 {
		return Revised{}, ErrNotTheirs
	}

	now := s.now().Truncate(time.Microsecond)
	revision := &Revision{
		DecisionID: decisionID, Ordinal: latest + 1,
		Body: reasoning, WrittenBy: subject.ID, WrittenAt: now,
	}
	if _, err := s.db.NewInsert().Model(revision).Exec(ctx); err != nil {
		return Revised{}, fmt.Errorf("record a revision: %w", err)
	}
	if err := noting(ctx, s.db, reasoning, revision.WrittenAt); err != nil {
		return Revised{}, err
	}

	// Every approval standing on the old words is taken back, and the decision
	// goes back to being a proposal. It is marked as having been approved
	// before — an approver meeting it again should know they are re-reading
	// something rather than seeing it for the first time — which is what the
	// kept approval rows say.
	//
	// Whole, because the argument is whole. Per row, revising one of
	// forty-four returned that row to the queue and left the other forty-three
	// saying the old thing under a decision that read as agreed.
	if _, err := s.db.NewUpdate().Model((*Approval)(nil)).
		Set(`"withdrawn_at" = ?`, now).
		Set(`"withdrawn_by" = ?`, subject.ID).
		Where(`"decision_id" = ?`, decisionID).
		Where(`"withdrawn_at" IS NULL`).Exec(ctx); err != nil {
		return Revised{}, fmt.Errorf("withdraw the approvals on what was revised: %w", err)
	}
	// Who agreed, read from the rows this revision withdrew rather than
	// before it. An agreement committed between a read and the write would be
	// withdrawn by the write and missing from the read.
	withdrawn, err := s.agreementsWithdrawn(ctx, subject, decisionID, now, rows)
	if err != nil {
		return Revised{}, err
	}
	if _, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set(`"revision_id" = ?`, revision.ID).
		Where(`"id" = ?`, decisionID).Exec(ctx); err != nil {
		return Revised{}, fmt.Errorf("record a revision: %w", err)
	}
	decision.RevisionID = &revision.ID

	// Keyed under the issue each row is read as, which is the key every live
	// row about that issue holds, whatever it was filed under.
	filed := make([]int64, 0, len(rows))
	for _, row := range rows {
		filed = append(filed, row.VulnerabilityID)
	}
	issueOf, err := finding.IssuesOf(ctx, s.db, filed)
	if err != nil {
		return Revised{}, err
	}
	occurrences := make([]Occurrence, 0, len(rows))
	for _, row := range rows {
		occurrences = append(occurrences, Occurrence{
			ProductID: row.ProductID, VulnerabilityID: issueOf[row.VulnerabilityID],
			OccurrenceIdentity: row.OccurrenceIdentity,
			ComponentUpstream:  orEmpty(row.ComponentUpstreamVersion),
			ConsumerUpstream:   orEmpty(row.ConsumerUpstreamVersion),
		})
	}
	for i, row := range rows {
		// Retaken, because revising a withdrawn or lapsed decision brings it back
		// to life and the key is what the uniqueness rule is enforced through.
		// Without it the row is live and holds nothing, the unique index
		// cannot see it, and a second contradictory decision about the same code
		// is accepted, both approvable, with one silently governing.
		key := liveKeyFor(occurrences[i], decision.Outcome.StandsAtAnyVersion())
		if _, err := s.db.NewUpdate().Model((*DecisionOccurrence)(nil)).
			Set(`"state" = ?`, Proposed).
			Set(`"live_key" = ?`, key).
			// Whatever was asked for has been answered, or at least responded
			// to. Leaving the mark would keep the decision out of the approval
			// queue forever, which is the failure that makes sending back
			// unusable.
			Set(`"sent_back_at" = ?`, nil).
			// Live again, so it has no moment it stopped applying.
			Set(`"ended_at" = ?`, nil).
			Where(`"id" = ?`, row.ID).Exec(ctx); err != nil {
			// Another decision has taken the occurrence since this one ended. The
			// unique index is the only thing that can say so, for the reason
			// proposing relies on it.
			if database.IsDuplicate(err) {
				// The occurrence this row refused on, not every occurrence of the
				// decision: its rows still standing are live at theirs, and
				// named first they would be offered as the decision to revise.
				return Revised{}, &occurrenceTaken{occurrences: []Occurrence{occurrences[i]}}
			}
			return Revised{}, fmt.Errorf("record a revision: %w", err)
		}
	}
	return Revised{Revision: revision, Withdrawn: withdrawn}, nil
}

// Withdraw takes a decision back.
//
// Whole, because an argument is whole: withdrawing part of one is setting rows
// aside, which is a different act with a different record.
//
// No approval needed, for the same reason revising needs none: it puts risk
// back on the table rather than taking it off.
//
// It answers the code findings whose agreed dismissal it took back, each of which is
// back in the queue.
func (s *Store) Withdraw(ctx context.Context, subject access.Subject, decisionID int64) ([]Reopened, error) {
	var reopened []Reopened
	// Both writes or neither. Half of this leaves a decision reading as agreed to
	// with every agreement marked withdrawn — which is the state the whole
	// approval record exists to make impossible.
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		decision, rows, err := within.writableRows(ctx, subject, decisionID, mayDecideOn)
		if err != nil {
			return err
		}
		reopened = nil
		for _, row := range rows {
			if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
				return ErrNotTheirs
			}
		}
		if decision.Outcome == Dismissed || decision.Outcome == NotSecurity {
			if err := tx.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).
				ColumnExpr(`DISTINCT "de"."product_id" AS "product_id", "de"."occurrence_identity" AS "occurrence_identity"`).
				Where(`"de"."decision_id" = ?`, decisionID).
				Where(`"de"."state" = ?`, Approved).
				Where(`"de"."vulnerability_id" IN (SELECT "rv"."id" FROM "vulnerability" AS "rv" WHERE "rv"."kind" = ?)`,
					string(kind.Rule)).
				Scan(ctx, &reopened); err != nil {
				return fmt.Errorf("read the code findings the decision dismissed: %w", err)
			}
		}
		now := s.now().Truncate(time.Microsecond)
		if _, err := tx.NewUpdate().Model((*Approval)(nil)).
			Set(`"withdrawn_at" = ?`, now).
			Set(`"withdrawn_by" = ?`, subject.ID).
			Where(`"decision_id" = ?`, decisionID).
			Where(`"withdrawn_at" IS NULL`).Exec(ctx); err != nil {
			return fmt.Errorf("withdraw a decision: %w", err)
		}
		if _, err := tx.NewUpdate().Model((*DecisionOccurrence)(nil)).
			Set(`"state" = ?`, Withdrawn).
			Set(`"ended_at" = ?`, now).
			// Released, so the occurrences are open to a fresh decision. A withdrawn
			// decision is history, and history must not stop anybody deciding.
			Set(`"live_key" = ?`, nil).
			Where(`"decision_id" = ?`, decisionID).
			// A row that has already ended keeps its state and its end
			// date: a lapse says when and why it stopped applying, and the
			// decision then reads as partly lapsed rather than withdrawn.
			Where(`"state" IN (?)`, bun.List([]State{Proposed, Approved})).
			Exec(ctx); err != nil {
			return fmt.Errorf("withdraw a decision: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return reopened, nil
}

// Reopened is a code finding an agreed dismissal no longer holds out of the queue.
type Reopened struct {
	ProductID          int64  `bun:"product_id"`
	OccurrenceIdentity string `bun:"occurrence_identity"`
}

// UndoBatch takes back everything one bulk approval agreed to.
//
// A reviewer may approve a long selection in one action, so undoing has to be
// available at the same size. Hunting for what a bulk approval touched, one
// row at a time, is not an undo anybody will actually use.
func (s *Store) UndoBatch(ctx context.Context, subject access.Subject, batch string) (Undone, error) {
	var undone Undone
	// Applied whole, and every read it decides from is inside it. Reading
	// which rows a batch covered and then writing outside that read lets
	// a row withdrawn in between be flipped back to waiting.
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		var err error
		undone, err = within.undoBatch(ctx, subject, batch)
		return err
	})
	return undone, err
}

// Undone is what taking a bulk approval back did, and who is waiting to hear
// about it.
//
// An undo is one of the two outcomes a proposer is told about, because it is
// the one nobody expects: it reverses something they were relying on, and
// everything else that happens to a decision is either what they asked for or
// something they did themselves.
type Undone struct {
	// Rows is how many rows returned to waiting.
	Rows int64
	// Told is who to tell, once each.
	Told []ForPerson
}

// ForPerson is somebody with something to hear, and enough to say it with: a
// representative row to link to, how many rows are theirs, and whether any of
// them is about a finding nobody has announced — which is what decides what
// may leave this deployment.
//
// Read off the rows rather than off a representative. A decision is one action
// over many occurrences whose rows need not agree about visibility, so the earliest
// row being public says nothing about the rest.
type ForPerson struct {
	PersonID             int64
	DecisionOccurrenceID int64
	// ProductID is the product the representative row is in, which is
	// what a telling about these rows is narrowed by later. A person's set
	// may span products; the representative names one of them, the same way
	// DecisionID does.
	ProductID       int64
	VulnerabilityID int64
	Rows            int
	// Undisclosed says any of the rows is withheld: undisclosed or internal.
	// Internal says any is internal work.
	Undisclosed bool
	Internal    bool
	// Probable says the rows were decisions on code findings a run paired only
	// probably, rather than decisions the code moved under.
	Probable bool
	// RatedWorse says the rows lapsed because the issue was rated worse,
	// rather than because the code moved.
	RatedWorse bool
}

func (s *Store) undoBatch(ctx context.Context, subject access.Subject, batch string) (Undone, error) {
	now := s.now().Truncate(time.Microsecond)

	// Narrowed to what this person may reach before anything is undone. A
	// batch is one reviewer's afternoon and may span products, so undoing it
	// wholesale would let somebody act on products they hold nothing on.
	//
	// And to the agreements this person gave. A batch is named by whoever
	// gives it, so two reviewers may each have one of the same name, and
	// undoing yours is not a way to take back somebody else's agreement.
	var occurrences []int64
	covered := s.db.NewSelect().Model((*Approval)(nil)).
		ColumnExpr(`"d"."id"`).
		Join(`JOIN "decision_occurrence" AS "d" ON "d"."decision_id" = "da"."decision_id"`).
		Where(`"da"."batch" = ?`, batch).Where(`"da"."withdrawn_at" IS NULL`).
		Where(`"da"."approved_by" = ?`, subject.ID)
	covered = approvableBy(covered, subject, "d")
	if err := covered.Scan(ctx, &occurrences); err != nil {
		return Undone{}, fmt.Errorf("read what that approval covered: %w", err)
	}
	if len(occurrences) == 0 {
		return Undone{}, nil
	}

	// A decision this person reaches only part of is left alone whole.
	//
	// The agreement is recorded against the decision, so taking it back takes it
	// back for every row — and keying the two writes on different units left
	// the rows outside this person's reach standing as approved under an
	// agreement the record says was withdrawn, which is the state the approval
	// record exists to make impossible. Withdraw refuses a decision it cannot act
	// on whole for the same reason.
	decisions, occurrences, err := s.wholeDecisions(ctx, occurrences)
	if err != nil {
		return Undone{}, err
	}
	// A confirmation a flaw record rests on stands: its flaw is judged
	// instead, and nothing about the decision changes again. The stamps are
	// read before the flaw records are asked about, and every decision undone is
	// restamped from them, as every writer of a decision is (writableRows).
	stamps, err := s.stampsOf(ctx, decisions)
	if err != nil {
		return Undone{}, err
	}
	if decisions, occurrences, err = s.leavingRecordedAsFlaw(ctx, decisions, occurrences); err != nil {
		return Undone{}, err
	}
	if len(decisions) == 0 {
		return Undone{}, nil
	}
	for _, id := range decisions {
		if err := s.restamp(ctx, id, stamps[id]); err != nil {
			return Undone{}, err
		}
	}

	// The proposers, read inside the same transaction as the writes
	// that follow and before them, because what is being reported is who
	// wrote the decisions this batch agreed to — which is a fact about the
	// rows that the undo does not change.
	told, err := s.proposersOf(ctx, occurrences)
	if err != nil {
		return Undone{}, err
	}

	if _, err := s.db.NewUpdate().Model((*Approval)(nil)).
		Set(`"withdrawn_at" = ?`, now).
		Set(`"withdrawn_by" = ?`, subject.ID).
		Where(`"batch" = ?`, batch).Where(`"withdrawn_at" IS NULL`).
		Where(`"approved_by" = ?`, subject.ID).
		Where(`"decision_id" IN (?)`, bun.List(decisions)).Exec(ctx); err != nil {
		return Undone{}, fmt.Errorf("undo an approval: %w", err)
	}
	rows, err := s.returnToWaiting(ctx, decisions)
	if err != nil {
		return Undone{}, fmt.Errorf("undo an approval: %w", err)
	}
	return Undone{Rows: rows, Told: told}, nil
}

// returnToWaiting puts the approved rows of these decisions back in the queue,
// once no agreement to them still stands, and says how many it moved.
//
// Back to proposed rather than withdrawn: the decisions still stand, and it is
// the agreement to them that was taken back. A row may carry more than
// one agreement, so a row another standing agreement holds stays approved.
//
// Approved rows only. A lapsed or withdrawn row has ended and holds no live
// key; returned to proposed it would wait for approval with nothing enforcing
// that one decision stands at its occurrence.
//
// Counted from the write rather than from the candidates, because both
// conditions exclude rows the caller named.
func (s *Store) returnToWaiting(ctx context.Context, decisions []int64) (int64, error) {
	res, err := s.db.NewUpdate().Model((*DecisionOccurrence)(nil)).
		Set(`"state" = ?`, Proposed).
		// A decision sent back and then approved, with the approval later taken
		// back, would otherwise be proposed, need approval, and sit in no
		// queue at all.
		Set(`"sent_back_at" = ?`, nil).
		Where(`"de"."decision_id" IN (?)`, bun.List(decisions)).
		Where(`"de"."state" = ?`, Approved).
		Where(`NOT EXISTS (SELECT 1 FROM "decision_approval" AS "still" ` +
			`WHERE "still"."decision_id" = "de"."decision_id" AND "still"."withdrawn_at" IS NULL)`).
		Exec(ctx)
	if err != nil {
		return 0, err
	}
	return database.Affected(res)
}

// leavingRecordedAsFlaw is these decisions and their rows without the decisions about a
// code finding recorded as a flaw.
func (s *Store) leavingRecordedAsFlaw(ctx context.Context, decisions, occurrences []int64) ([]int64, []int64, error) {
	handed, err := s.recordedAsFlaw(ctx, decisions)
	if err != nil || len(handed) == 0 {
		return decisions, occurrences, err
	}
	kept := make([]int64, 0, len(decisions))
	for _, id := range decisions {
		if !handed[id] {
			kept = append(kept, id)
		}
	}
	if len(kept) == 0 {
		return nil, nil, nil
	}
	var rows []int64
	if err := database.IDsInBatches(ctx, occurrences, func(ctx context.Context, batch []int64) error {
		var some []int64
		if err := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).Column("id").
			Where(`"de"."id" IN (?)`, bun.List(batch)).
			Where(`"de"."decision_id" IN (?)`, bun.List(kept)).
			Scan(ctx, &some); err != nil {
			return err
		}
		rows = append(rows, some...)
		return nil
	}); err != nil {
		return nil, nil, fmt.Errorf("read what that approval covered: %w", err)
	}
	return kept, rows, nil
}

// wholeDecisions keeps only the decisions every one of whose rows is in reached, and
// returns those decisions and their rows.
//
// The set is read with no narrowing, because the question is not which rows
// this person reaches but whether they reach the whole decision: a decision is one
// action over many occurrences whose rows need not agree about visibility, and the
// agreement given to it is one row keyed on the decision.
func (s *Store) wholeDecisions(ctx context.Context, reached []int64) ([]int64, []int64, error) {
	var rows []struct {
		ID         int64 `bun:"id"`
		DecisionID int64 `bun:"decision_id"`
	}
	if err := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		Column("id", "decision_id").
		Where(`"de"."decision_id" IN (SELECT "sibling"."decision_id" FROM "decision_occurrence" AS "sibling"
			WHERE "sibling"."id" IN (?))`, bun.List(reached)).
		Scan(ctx, &rows); err != nil {
		return nil, nil, fmt.Errorf("read what that approval covered: %w", err)
	}
	within := make(map[int64]bool, len(reached))
	for _, id := range reached {
		within[id] = true
	}
	partial := map[int64]bool{}
	for _, row := range rows {
		if !within[row.ID] {
			partial[row.DecisionID] = true
		}
	}
	decisions, kept := make([]int64, 0, len(rows)), make([]int64, 0, len(rows))
	seen := map[int64]bool{}
	for _, row := range rows {
		if partial[row.DecisionID] {
			continue
		}
		if !seen[row.DecisionID] {
			seen[row.DecisionID] = true
			decisions = append(decisions, row.DecisionID)
		}
		kept = append(kept, row.ID)
	}
	return decisions, kept, nil
}

// agreementsWithdrawn gathers whose agreement on a decision the subject withdrew
// at a moment, one entry each, leaving out the subject. Each entry carries the decision's earliest row as the
// representative, and whether any of its rows is undisclosed, read off the rows
// rather than off the representative.
func (s *Store) agreementsWithdrawn(ctx context.Context, subject access.Subject, decisionID int64,
	at time.Time, rows []DecisionOccurrence) ([]ForPerson, error) {

	if len(rows) == 0 {
		return nil, nil
	}
	var approvers []int64
	if err := s.db.NewSelect().Model((*Approval)(nil)).
		ColumnExpr(`DISTINCT "da"."approved_by"`).
		Where(`"da"."decision_id" = ?`, decisionID).
		Where(`"da"."withdrawn_at" = ?`, at).
		Where(`"da"."withdrawn_by" = ?`, subject.ID).
		Where(`"da"."approved_by" <> ?`, subject.ID).
		OrderExpr(`"da"."approved_by" ASC`).
		Scan(ctx, &approvers); err != nil {
		return nil, fmt.Errorf("read who agreed to this: %w", err)
	}
	undisclosed, internal := false, false
	first := rows[0]
	for _, row := range rows {
		if row.Visibility != access.Public {
			undisclosed = true
		}
		if row.Visibility == access.Internal {
			internal = true
		}
		if row.ID < first.ID {
			first = row
		}
	}
	told := make([]ForPerson, 0, len(approvers))
	for _, person := range approvers {
		told = append(told, ForPerson{
			PersonID: person, DecisionOccurrenceID: first.ID,
			ProductID: first.ProductID, VulnerabilityID: first.VulnerabilityID,
			Rows: len(rows), Undisclosed: undisclosed, Internal: internal,
		})
	}
	return told, nil
}

// proposersOfAll is proposersOf over a set of any size: read chunk rows at a
// time and merged, so a person is one entry however many chunks their
// rows fall in. The representative is their earliest row.
func (s *Store) proposersOfAll(ctx context.Context, ids []int64, chunk int) ([]ForPerson, error) {
	sorted := slices.Clone(ids)
	slices.Sort(sorted)
	at := map[int64]int{}
	var told []ForPerson
	for start := 0; start < len(sorted); start += chunk {
		chunk, err := s.proposersOf(ctx, sorted[start:min(start+chunk, len(sorted))])
		if err != nil {
			return told, err
		}
		for _, one := range chunk {
			i, seen := at[one.PersonID]
			if !seen {
				at[one.PersonID] = len(told)
				told = append(told, one)
				continue
			}
			told[i].Rows += one.Rows
			told[i].Undisclosed = told[i].Undisclosed || one.Undisclosed
			told[i].Internal = told[i].Internal || one.Internal
		}
	}
	return told, nil
}

// proposersOf gathers who wrote a set of rows, one entry each.
func (s *Store) proposersOf(ctx context.Context, ids []int64) ([]ForPerson, error) {
	var rows []DecisionOccurrence
	if err := s.db.NewSelect().Model(&rows).
		Column("id", "proposed_by", "visibility", "product_id", "vulnerability_id").
		Where(`"id" IN (?)`, bun.List(ids)).Order("id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who proposed these: %w", err)
	}
	at := map[int64]int{}
	told := make([]ForPerson, 0, 4)
	for _, row := range rows {
		i, seen := at[row.ProposedBy]
		if !seen {
			at[row.ProposedBy] = len(told)
			told = append(told, ForPerson{
				PersonID: row.ProposedBy, DecisionOccurrenceID: row.ID,
				ProductID: row.ProductID, VulnerabilityID: row.VulnerabilityID,
			})
			i = len(told) - 1
		}
		told[i].Rows++
		if row.Visibility != access.Public {
			told[i].Undisclosed = true
		}
		if row.Visibility == access.Internal {
			told[i].Internal = true
		}
	}
	return told, nil
}

// authorOf returns who wrote the reasoning a decision currently rests on.
func (s *Store) authorOf(ctx context.Context, decision Decision) (int64, error) {
	if decision.RevisionID == nil {
		return 0, ErrNothingToApprove
	}
	revision := new(Revision)
	if err := s.db.NewSelect().Model(revision).
		Where(`"id" = ?`, *decision.RevisionID).Scan(ctx); err != nil {
		return 0, fmt.Errorf("read who wrote this: %w", err)
	}
	return revision.WrittenBy, nil
}

// secondPerson refuses an agreement to a decision from somebody who proposed any
// row of it or wrote any of its reasoning.
//
// Asked by every write that makes a row stand on an agreement — one given
// now and one carried from an earlier decision — so no path to a standing row
// skips the control REQ-24 names.
func (s *Store) secondPerson(ctx context.Context, decisionID, approver int64) error {
	ownWords, err := s.db.NewSelect().Model((*Revision)(nil)).
		Where(`"dr"."decision_id" = ?`, decisionID).
		Where(`"dr"."written_by" = ?`, approver).
		Exists(ctx)
	if err != nil {
		return fmt.Errorf("read who wrote this: %w", err)
	}
	ownRows, err := s.db.NewSelect().Model((*DecisionOccurrence)(nil)).
		Where(`"de"."decision_id" = ?`, decisionID).
		Where(`"de"."proposed_by" = ?`, approver).
		Exists(ctx)
	if err != nil {
		return fmt.Errorf("read who proposed this: %w", err)
	}
	if ownWords || ownRows {
		return ErrSamePerson
	}
	return nil
}

// covering counts the open findings a decision covers right now.
//
// The same match a finding makes when it asks whether a decision applies to
// it: the occurrence, and both upstream versions. Read at the moment of approval
// and kept, because a decision reaches by matching and so covers more as builds
// appear — with nobody having acted, and nobody having agreed to the larger
// number.
//
// One statement over every row of the decision, whatever its size. A decision over a
// kernel is two thousand rows, and a count per row was a count per round trip.
func (s *Store) covering(ctx context.Context, subject access.Subject, ids []int64) (int, error) {
	// Narrowed like every other count here, per product. What is stored on
	// the approval is served back, so an unnarrowed count discloses how many
	// undisclosed findings sit behind a decision to somebody who may not read one.
	covered, err := s.db.NewSelect().
		TableExpr(finding.DecisionOccurrences).
		Join(`JOIN "finding" AS "f" ON `+finding.DecisionOccurrenceOf("f")).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id" AND "st"."product_id" = "de"."product_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Where(`"de"."id" IN (?)`, bun.List(ids)).
		Where(`"f"."closed_at" IS NULL`).
		Apply(ofKinds(kind.Decisions, "f")).
		Where(finding.KeyMatches).
		Apply(readableFindingsBy(subject, "f", `"st"."product_id"`)).
		Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count what this covers: %w", err)
	}
	return int(covered), nil
}
