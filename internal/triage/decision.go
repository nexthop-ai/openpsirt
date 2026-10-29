// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage

import (
	"context"
	"database/sql"
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

// Decision is one proposer's action: what an approver reads and agrees to.
//
// A decision about a finding writes one row per occurrence, and a decision
// about many issues writes one per issue and per occurrence. Those rows stay that
// fine, because each is keyed and lapses on its own. What a second person
// reads is the action — one argument, with its reach — and the queue,
// approval, sending back and undoing all work on that rather than on rows.
type Decision struct {
	bun.BaseModel `bun:"table:decision,alias:cl"`

	ID         int64        `bun:"id,pk,autoincrement"`
	Kind       DecisionKind `bun:"kind,notnull"`
	ProposedBy int64        `bun:"proposed_by,notnull"`
	ProposedAt time.Time    `bun:"proposed_at,notnull"`
	// DerivedFrom is the decision this one came from: the approved decision an
	// extension carries to a new issue, or the decision an approver set some rows
	// aside from when agreeing to the rest.
	DerivedFrom *int64 `bun:"derived_from"`
	// SelectedBy is how a bulk set was narrowed. Held on the decision as well as
	// on its rows, so a decision whose rows were all set aside still says how it
	// was found.
	SelectedBy *string `bun:"selected_by"`
	// SelectedWhere, SelectedMatched and SelectedNamed are the same question
	// answered by something an approver can re-run: the text the candidate
	// list was narrowed by, how many issues that narrowing reached when the
	// decision was written, and how many were then named. Nil on a decision that was
	// not a bulk selection.
	SelectedWhere   *string `bun:"selected_where"`
	SelectedMatched *int    `bun:"selected_matched"`
	SelectedNamed   *int    `bun:"selected_named"`
	// Outcome is what the decision says, held once because one act is one
	// argument.
	//
	// Held on the decision rather than on each row: a decision reaching many
	// occurrences held per row is many copies of one sentence, each revisable on
	// its own, and revising one would leave the rest saying the old thing
	// while the decision read as agreed. In the measured deployment every one of
	// these was constant across every row of every decision.
	Outcome Outcome `bun:"outcome,notnull"`
	// Justification is one of the recognized reasons, for the outcome that
	// states something does not apply — where which reason it is *is* the
	// decision.
	Justification *string `bun:"justification"`
	// Mitigation is what a holder can do about it.
	//
	// Required where the decision is that something already stops it, which is
	// what that decision says. Allowed and optional where the decision is that this
	// will not be fixed, because a standing property of a shipped feature
	// often has a real answer — use the other protocol, reach it from the
	// management network only — and the published document has a field for
	// exactly that. Meaningless with any other outcome.
	Mitigation *string `bun:"mitigation"`
	// Scope is whom a statement published from this decision holds for, where
	// the proposer stated it. Nil lets the outcome and the reason decide, which
	// is what nearly every decision does.
	Scope *Scope `bun:"scope"`
	// DeferredUntil is when somebody will look again, for the one outcome that
	// expires on a date rather than on the code changing.
	DeferredUntil *time.Time `bun:"deferred_until"`
	// FixedVersion is the package version whoever packages this states the fix
	// arrived in. Required for the outcome that states the fix is already here
	// and meaningless with any other.
	//
	// Stored beside the scanner's own answer rather than instead of it: that
	// one is what the vulnerability data says about the upstream project, and
	// this one is what a distribution says about its own package. The two
	// disagree exactly when this outcome is the right one.
	FixedVersion *string `bun:"fixed_version"`
	// CommittedTo is when the work promised here will be done, and UpgradeTo
	// the version an upgrade moves to. Both set only for the two outcomes that
	// promise to act.
	CommittedTo *time.Time `bun:"committed_to"`
	UpgradeTo   *string    `bun:"upgrade_to"`
	// RevisionID is the reasoning that currently stands. An approval points at
	// one revision rather than at the decision, so this moving is exactly what
	// withdraws every approval given for what it used to say.
	RevisionID *int64 `bun:"revision_id"`
	// Elsewhere is where this is being argued about or worked on outside
	// here: a ticket, a thread, a change. Stored and never fetched — a
	// link has no egress at all, which is what makes it available without
	// a deployment first deciding to let anything out.
	Elsewhere string `bun:"elsewhere"`
}

// PointAt records where a decision's work is happening.
//
// Anybody who may argue about the decision may set it, which is the same right
// that made the decision: a link is a note about where the conversation is, not a
// decision, and needing a second person for it would leave it unset.
//
// Sent empty it is cleared, because a stale link is worse than none — it sends
// somebody to a ticket that closed for a different reason.
func (s *Store) PointAt(ctx context.Context, subject access.Subject, decisionID int64,
	where string) error {

	// Read as what they may see, then checked row by row for what they may
	// argue about. The two are asked separately because the second
	// question names the issue: somebody brought into one case may argue
	// about it , and a check that only knew the product would refuse them.
	_, rows, err := s.readableDecisionRows(ctx, subject, decisionID)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return ErrNotTheirs
	}
	for _, row := range rows {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return ErrNotTheirs
		}
	}
	where = strings.TrimSpace(where)
	if err := markdown.Addressable(where); err != nil {
		return err
	}
	if _, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set(`"elsewhere" = ?`, where).
		Where(`"id" = ?`, decisionID).Exec(ctx); err != nil {
		return fmt.Errorf("record where the work is: %w", err)
	}
	return nil
}

// argument is what this decision says, in the shape a new decision is recorded from.
//
// Used where a decision is split rather than re-argued: an approver setting rows
// aside is saying "not these", not "something else about these", so the rows
// that move carry the argument they were made under.
func (c Decision) argument() Proposal {
	p := Proposal{
		Outcome:       c.Outcome,
		DeferredUntil: c.DeferredUntil,
		CommittedTo:   c.CommittedTo,
		Mitigation:    orEmpty(c.Mitigation),
		FixedVersion:  orEmpty(c.FixedVersion),
		UpgradeTo:     orEmpty(c.UpgradeTo),
	}
	if c.Scope != nil {
		p.Scope = *c.Scope
	}
	if c.Justification != nil {
		p.Justification = Justification(*c.Justification)
	}
	return p
}

// DecisionKind is what sort of action a decision was.
type DecisionKind string

const (
	// FindingDecision is one decision about one issue in one component,
	// covering the occurrences it sits at. A re-affirmation is one too.
	FindingDecision DecisionKind = "finding"
	// BulkDecision is one decision about many issues at one component.
	BulkDecision DecisionKind = "bulk"
	// ExtensionDecision carries an approved decision to a new issue at the same
	// component under the same consumer, with the same justification.
	ExtensionDecision DecisionKind = "extension"
	// ReturnedDecision holds the rows an approver set aside from a decision they
	// agreed the rest of. It goes back to whoever proposed them.
	ReturnedDecision DecisionKind = "returned"
)

// DecisionKinds is every sort of action a decision can be.
func DecisionKinds() []DecisionKind {
	return []DecisionKind{FindingDecision, BulkDecision, ExtensionDecision, ReturnedDecision}
}

// newDecision records an action and what it argues, inside whatever transaction is
// writing its rows.
//
// The argument comes from a proposal because the two are one thing: a decision
// with no outcome is not something a second person can agree to, and the rows
// underneath carry where it applies rather than what it says.
func (s *Store) newDecision(ctx context.Context, kind DecisionKind, by int64, derivedFrom *int64,
	selectedBy string, p Proposal) (*Decision, error) {

	return s.newDecisionNarrowed(ctx, kind, by, derivedFrom, selectedBy, nil, p)
}

// newDecisionNarrowed is the same, for the one action that also records a
// narrowing something other than the proposer can check.
func (s *Store) newDecisionNarrowed(ctx context.Context, kind DecisionKind, by int64,
	derivedFrom *int64, selectedBy string, narrowing *finding.Narrowing,
	p Proposal) (*Decision, error) {

	decision := &Decision{
		Kind: kind, ProposedBy: by, ProposedAt: s.now().Truncate(time.Microsecond),
		DerivedFrom:   derivedFrom,
		Outcome:       p.Outcome,
		DeferredUntil: p.DeferredUntil,
		CommittedTo:   p.CommittedTo,
	}
	if strings.TrimSpace(selectedBy) != "" {
		how := selectedBy
		decision.SelectedBy = &how
	}
	if narrowing != nil {
		where, matched, named := narrowing.Contains, narrowing.Matched, narrowing.Named
		decision.SelectedWhere = &where
		decision.SelectedMatched = &matched
		decision.SelectedNamed = &named
	}
	if strings.TrimSpace(p.Mitigation) != "" {
		named := strings.TrimSpace(p.Mitigation)
		decision.Mitigation = &named
	}
	if p.Scope != "" {
		stated := p.Scope
		decision.Scope = &stated
	}
	// The version an upgrade moves to, carried on the decision rather than in a
	// record beside it, so what somebody decided and what the release is
	// waiting on cannot come to disagree.
	if p.Outcome == UpgradeNeeded && strings.TrimSpace(p.UpgradeTo) != "" {
		moving := strings.TrimSpace(p.UpgradeTo)
		decision.UpgradeTo = &moving
	}
	if p.Outcome.NeedsJustification() {
		stated := string(p.Justification)
		decision.Justification = &stated
	}
	if p.Outcome == AlreadyFixed {
		// Read through the same normalization as every other version here, so
		// that a value stored with surrounding space and one typed without it
		// do not read as two different decisions.
		arrived := version(p.FixedVersion)
		decision.FixedVersion = &arrived
	}
	if _, err := s.db.NewInsert().Model(decision).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record a decision: %w", err)
	}
	// The reasoning, written with the decision rather than with its rows. The two
	// go together: a decision with no reasoning is not something a second person
	// can agree to, and leaving it to a later write is how something reaches
	// the queue with nothing in it to review.
	revision := &Revision{
		DecisionID: decision.ID, Ordinal: 1,
		Body: p.Reasoning, WrittenBy: by, WrittenAt: decision.ProposedAt,
	}
	if _, err := s.db.NewInsert().Model(revision).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record the reasoning: %w", err)
	}
	if _, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set(`"revision_id" = ?`, revision.ID).
		Where(`"id" = ?`, decision.ID).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record the reasoning: %w", err)
	}
	decision.RevisionID = &revision.ID
	if err := s.recordMadeOn(ctx, decision.ID, p); err != nil {
		return nil, err
	}
	if err := noting(ctx, s.db, p.Reasoning, decision.ProposedAt); err != nil {
		return nil, err
	}
	return decision, nil
}

// ErrNotExtendable is returned when a decision cannot be carried to a new issue.
var ErrNotExtendable = refusal.New("that decision cannot be extended")

// Extend records the same decision an approved decision made, against a new issue
// at the same occurrences.
//
// The everyday case rather than the rare one: every nightly scan adds issues
// to components that already carry agreed decisions — a new flaw in a kernel
// driver the image does not build — and each arrived with no decision. An
// extension is a decision of its own, recorded as derived from the one it
// carries, and it needs a second person like any other dismissal: the approver
// is told the argument was read once already, not that it was agreed to twice
// .
//
// Everything it turns on is read inside the transaction that writes: whether
// the source is approved, and what it was a decision about.
func (s *Store) Extend(ctx context.Context, subject access.Subject, from int64,
	proposals []Proposal) ([]*DecisionOccurrence, error) {

	if len(proposals) == 0 {
		return nil, nil
	}

	var recorded []*DecisionOccurrence
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		recorded = recorded[:0]
		if err := within.allowed(ctx, subject, proposals); err != nil {
			return err
		}

		source, err := within.extendable(ctx, subject, from, proposals)
		if err != nil {
			return err
		}
		// The gate, worked out here for the reason every other write path
		// works it out here.
		if err := within.gate(ctx, subject, proposals); err != nil {
			return err
		}
		// The source's statement of whom it holds for travels with its
		// conclusion. A proposal carrying none takes it; one stating another
		// was refused above as a different decision.
		carried := proposals[0]
		carried.Scope = scopeOf(source.Scope)
		decision, err := within.newDecision(ctx, ExtensionDecision, subject.ID, &source.ID, "", carried)
		if err != nil {
			return err
		}
		recorded, err = within.proposeAll(ctx, decision, proposals)
		return err
	})
	if err != nil {
		return nil, s.alreadyDecided(ctx, err, occurrencesOf(proposals))
	}
	return recorded, nil
}

// extendable reads the decision being carried and checks it can be.
//
// Three things have to hold, and each is a decision the extension would otherwise
// be making on the source's behalf: the source is agreed to — every row of it
// approved, none withdrawn or lapsed — so an extension never carries an
// argument nobody agreed with; the new rows sit at occurrences the source sits at,
// in the same product, because "the same argument" is about the same code
// under the same consumer; and the outcome and justification are the source's,
// because a different conclusion is a different decision.
func (s *Store) extendable(ctx context.Context, subject access.Subject, from int64,
	proposals []Proposal) (*Decision, error) {

	source := new(Decision)
	if err := s.db.NewSelect().Model(source).Where(`"id" = ?`, from).Scan(ctx); err != nil {
		return nil, database.FromRead(err, ErrNotTheirs, fmt.Sprintf("read decision %d", from))
	}
	var rows []DecisionOccurrence
	if err := s.db.NewSelect().Model(&rows).Where(`"decision_id" = ?`, from).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what that decision covers: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrNotTheirs
	}
	// Asked of every row rather than of the first. A decision is one action over
	// many occurrences and may cover more than one issue, so comparing against the
	// head accepted an extension duplicating any issue the source already
	// covers but did not happen to be written first.
	occurrences := map[string]bool{}
	issues, products := map[int64]bool{}, map[int64]bool{}
	for _, row := range rows {
		if !readable(subject, row.ProductID, row.Visibility) {
			return nil, ErrNotTheirs
		}
		if row.State != Approved {
			return nil, fmt.Errorf("%w: it is %s, and only an approved decision carries", ErrNotExtendable, row.State)
		}
		occurrences[row.OccurrenceIdentity] = true
		issues[row.VulnerabilityID] = true
		products[row.ProductID] = true
	}
	for _, p := range proposals {
		if !products[p.Occurrence.ProductID] {
			return nil, fmt.Errorf("%w: it is about a different product", ErrNotExtendable)
		}
		if !occurrences[p.Occurrence.OccurrenceIdentity] {
			return nil, fmt.Errorf("%w: it is about a different component or consumer", ErrNotExtendable)
		}
		if issues[p.Occurrence.VulnerabilityID] {
			return nil, fmt.Errorf("%w: it already covers this issue", ErrNotExtendable)
		}
		if p.Outcome != source.Outcome || string(p.Justification) != orEmpty(source.Justification) {
			return nil, fmt.Errorf("%w: an extension keeps the outcome and justification it carries", ErrNotExtendable)
		}
		if p.Scope != "" && p.Scope != scopeOf(source.Scope) {
			return nil, fmt.Errorf("%w: an extension keeps whom the decision it carries holds for", ErrNotExtendable)
		}
	}
	return source, nil
}

// DecisionApproved is what agreeing to a decision did.
type DecisionApproved struct {
	// Approved is how many rows were agreed to.
	Approved int
	// Returned is the decision the rows set aside went into, where any were.
	Returned *Decision
	// ReturnedIn is the product those rows are in. A decision carries no
	// product of its own — it is one argument over many occurrences, and each
	// row holds the product — so it is read off the rows that moved,
	// for whoever has to say what the telling about them is about.
	ReturnedIn int64
	// ReturnedSecurityTesting says at least one row set aside is security testing work.
	ReturnedSecurityTesting bool
}

// ApproveDecision records a second person agreeing to a decision: every row in
// it, as one action, under the same rules each row is approved under.
//
// Rows may be set aside. An approver of a bulk decision who has found the handful
// of rows that do not look like the rest should not have to choose between
// refusing everything and agreeing to everything: the rest is approved as one
// decision, and the rows set aside go back to the proposer as a decision of their
// own, carrying the reason the way sending back does.
//
// Against one revision, not against the decision. The whole value of a second
// pair of eyes is that they read particular words; an approval that floats
// free of the words would still be standing after somebody rewrote them, and
// nothing would report that.
//
// The proposer may never be the approver, with no override. A one-person
// deployment therefore cannot approve anything, which is the control working
// rather than a gap in it.
func (s *Store) ApproveDecision(ctx context.Context, subject access.Subject, decisionID int64,
	batch string, except []int64, because string) (*DecisionApproved, error) {

	if len(except) > 0 {
		if strings.TrimSpace(because) == "" {
			return nil, refusal.Errorf("say why those are set aside: rows returned with no reason " +
				"are a round trip nobody learns from")
		}
		if err := markdown.Check(because); err != nil {
			return nil, err
		}
	}

	var result *DecisionApproved
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		var err error
		result, err = within.approveDecision(ctx, subject, decisionID, batch, except, because)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) approveDecision(ctx context.Context, subject access.Subject, decisionID int64,
	batch string, except []int64, because string) (*DecisionApproved, error) {

	decision, rows, err := s.writableRows(ctx, subject, decisionID, mayApproveOn)
	if err != nil {
		return nil, err
	}
	aside := make(map[int64]bool, len(except))
	for _, id := range except {
		aside[id] = true
	}
	// Every row named as set aside has to be one of this decision's. A stray
	// identifier is more likely a mistake than a wish, and silently ignoring
	// it would approve a row somebody meant to hold back.
	named := make(map[int64]bool, len(rows))
	for _, row := range rows {
		named[row.ID] = true
	}
	for id := range aside {
		if !named[id] {
			return nil, refusal.Errorf("occurrence %d is not part of decision %d", id, decisionID)
		}
	}
	if decision.RevisionID == nil {
		return nil, ErrNothingToApprove
	}
	// Refused before anybody agrees to it. A decision that the issue does not
	// apply, written before an incident in this product through it arrived,
	// is a decision the incident contradicts — and agreeing to it is
	// what would put the finding out of sight.
	//
	// Asked of the rows being agreed to rather than all of them, so an
	// approver can set the attacked issue aside and agree to the rest: what
	// is set aside goes back to its author, and the same rule meets it there.
	agreeing := make([]DecisionOccurrence, 0, len(rows))
	for _, row := range rows {
		if !aside[row.ID] {
			agreeing = append(agreeing, row)
		}
	}
	if err := s.refuseIfIncidentOn(ctx, decision, agreeing); err != nil {
		return nil, err
	}
	// Compared against whoever wrote the words being agreed to, not only
	// against whoever proposed the decision. An approval names one revision, so
	// the control is about the text — and anybody who may triage can revise,
	// which made "did you propose this" the wrong question: revise somebody
	// else's decision in your own words and you could then approve your own.
	author, err := s.authorOf(ctx, *decision)
	if err != nil {
		return nil, err
	}
	samePerson := author == subject.ID || decision.ProposedBy == subject.ID

	var approving, returning []int64
	var returnedIn int64
	var returnedSecurityTesting bool
	for _, row := range rows {
		if row.State != Proposed {
			continue
		}
		if aside[row.ID] {
			// Setting rows aside is an approver's act as much as agreeing
			// is — the rest of the decision is approved in the same action — so
			// the proposer naming their own rows as set aside would be acting
			// on their own decision.
			if samePerson {
				return nil, ErrSamePerson
			}
			returning = append(returning, row.ID)
			returnedIn = row.ProductID
			if row.Visibility == access.SecurityTesting {
				returnedSecurityTesting = true
			}
			continue
		}
		// A row already with the author is not waiting on an approver, and
		// agreeing to it before they answer would undo the sending back. It
		// is not in the queue for the same reason.
		if row.SentBackAt != nil {
			continue
		}
		if samePerson {
			return nil, ErrSamePerson
		}
		approving = append(approving, row.ID)
	}
	if len(approving) == 0 && len(returning) == 0 {
		return nil, ErrNothingToApprove
	}

	now := s.now().Truncate(time.Microsecond)
	result := &DecisionApproved{}
	if len(approving) > 0 {
		if err := s.agree(ctx, subject, *decision, approving, batch, now); err != nil {
			return nil, err
		}
		result.Approved = len(approving)
	}

	if len(returning) > 0 {
		// What an approver set aside is these rows, not a different decision
		// about them.
		returned, err := s.intoReturned(ctx, subject, decision, returning, because, now, "set rows aside")
		if err != nil {
			return nil, err
		}
		result.Returned = returned
		result.ReturnedIn = returnedIn
		result.ReturnedSecurityTesting = returnedSecurityTesting
	}
	return result, nil
}

// intoReturned moves rows still waiting on a decision into a decision of their own,
// derived from it, and records why as a comment there.
//
// The same argument, in a decision of its own. The reasoning travels with it,
// because a decision with none is one nobody can be asked to agree to. The rows
// sit with their author: they leave the review queue until the argument for
// them is stated again.
//
// Matched on what was read: still waiting, and still this decision's. A row an
// approval or a withdrawal moved since is not moved over it, and the whole
// act is taken again. The reason is a comment on the decision the rows went
// into, the way sending back records it: the author needs the words, and a
// reason kept anywhere else is one nobody reads.
func (s *Store) intoReturned(ctx context.Context, subject access.Subject, decision *Decision, ids []int64,
	because string, now time.Time, doing string) (*Decision, error) {

	carried := decision.argument()
	carried.MadeAs = decision.ID
	var err error
	if carried.Reasoning, err = s.reasoningOn(ctx, *decision); err != nil {
		return nil, err
	}
	returned, err := s.newDecision(ctx, ReturnedDecision, decision.ProposedBy, &decision.ID,
		orEmpty(decision.SelectedBy), carried)
	if err != nil {
		return nil, err
	}
	moved, err := s.db.NewUpdate().Model((*DecisionOccurrence)(nil)).
		Set(`"decision_id" = ?`, returned.ID).
		Set(`"sent_back_at" = ?`, now).
		Where(`"id" IN (?)`, bun.List(ids)).
		Where(`"decision_id" = ?`, decision.ID).
		Where(`"state" = ?`, Proposed).Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", doing, err)
	}
	if err := movedAll(moved, len(ids), doing); err != nil {
		return nil, err
	}
	if err := s.sayOn(ctx, subject, returned.ID, because, now); err != nil {
		return nil, err
	}
	return returned, nil
}

// agree records one person agreeing to a decision, and moves the rows it covers.
//
// One approval row, because one act is one argument: an approver reads the
// words once and agrees to them once, and a row per occurrence was a copy of that
// agreement that could go on standing after the words changed.
//
// The revision-bound control is the condition on the update. The approval
// names the revision it was given for, and the rows move only while that is
// still the reasoning the decision rests on. A revision landing in between leaves
// them unmoved, the matched count falls short, and the whole decision is refused
// rather than half of it agreed to.
func (s *Store) agree(ctx context.Context, subject access.Subject, decision Decision, ids []int64,
	batch string, now time.Time) error {

	if err := s.secondPerson(ctx, decision.ID, subject.ID); err != nil {
		return err
	}
	covered, err := s.covering(ctx, subject, ids)
	if err != nil {
		return err
	}
	approval := &Approval{
		DecisionID: decision.ID, RevisionID: *decision.RevisionID,
		ApprovedBy: subject.ID, ApprovedAt: now, Covered: &covered,
	}
	if strings.TrimSpace(batch) != "" {
		approval.Batch = &batch
	}
	if _, err := s.db.NewInsert().Model(approval).Exec(ctx); err != nil {
		return fmt.Errorf("record an approval: %w", err)
	}

	return s.approveWhileRevised(ctx, decision, ids, "record an approval",
		"the reasoning changed while this was being agreed to; read it again")
}

// approveWhileRevised moves rows waiting on a decision to approved, while the
// decision still rests on the revision the approval names, and refuses with
// changed where any row did not move.
//
// The count is the control here, so a count that cannot be read is a refusal
// rather than a pass. Read as optional, the whole revision-bound check would
// be skipped after the approval row was already written, leaving a decision
// agreed to under an approval naming reasoning that is no longer what it rests
// on.
func (s *Store) approveWhileRevised(ctx context.Context, decision Decision, ids []int64,
	doing, changed string) error {

	moved, err := s.db.NewUpdate().Model((*DecisionOccurrence)(nil)).
		Set(`"state" = ?`, Approved).
		Where(`"id" IN (?)`, bun.List(ids)).
		Where(`"state" = ?`, Proposed).
		Where(`EXISTS (SELECT 1 FROM "decision" AS "ac" WHERE "ac"."id" = ? AND "ac"."revision_id" = ?)`,
			decision.ID, *decision.RevisionID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", doing, err)
	}
	n, err := database.Affected(moved)
	if err != nil {
		return fmt.Errorf("%s: %w", doing, err)
	}
	if n != int64(len(ids)) {
		return refusal.Errorf("%s", changed)
	}
	return nil
}

// sayOn records one comment on a decision.
func (s *Store) sayOn(ctx context.Context, subject access.Subject, decisionID int64, body string,
	now time.Time) error {

	if strings.TrimSpace(body) == "" {
		return refusal.Errorf("a comment has to say something")
	}
	if err := markdown.Check(body); err != nil {
		return err
	}
	comment := &Comment{DecisionID: decisionID, Body: body, WrittenBy: subject.ID, WrittenAt: now}
	if _, err := s.db.NewInsert().Model(comment).Exec(ctx); err != nil {
		return fmt.Errorf("record a comment: %w", err)
	}
	return noting(ctx, s.db, body, now)
}

// reasoningOn is the words a decision currently rests on.
func (s *Store) reasoningOn(ctx context.Context, decision Decision) (string, error) {
	if decision.RevisionID == nil {
		return "", ErrNothingToApprove
	}
	revision := new(Revision)
	if err := s.db.NewSelect().Model(revision).
		Where(`"id" = ?`, *decision.RevisionID).Scan(ctx); err != nil {
		return "", fmt.Errorf("read what it says: %w", err)
	}
	return revision.Body, nil
}

// Split holds back part of a decision the proposer no longer wants to argue as one.
//
// The approver's side of this already existed and the proposer's did not.
// An approver reading a bulk decision may agree to most of it and set some rows
// aside; whoever wrote it could only withdraw the whole thing and start again,
// so "this holds for most of them but not those four" was unavailable to the
// person best placed to say it — and the same outliers that help an approver
// choose a subset were shown only to the approver.
//
// The same mechanism rather than a second one: the rows named move into a decision
// of their own, derived from this one, carrying the argument they were made
// under, with the reason recorded as a comment and the rows marked as sitting
// with their author. What happens next is a revision, which is the act that
// gives them an argument of their own.
//
// A proposer's act, as setting rows aside is an approver's. Each is refused
// to the other: an approver holding some of a decision back is agreeing to the
// rest in the same action, and a proposer doing that would be approving their
// own decision.
func (s *Store) Split(ctx context.Context, subject access.Subject, decisionID int64,
	rows []int64, because string) (*Decision, error) {

	if len(rows) == 0 {
		return nil, refusal.Errorf("say which rows are being held back")
	}
	if strings.TrimSpace(because) == "" {
		return nil, refusal.Errorf("say why these are being held back: a subset with no reason " +
			"is a decision nobody can read afterwards")
	}
	if err := markdown.Check(because); err != nil {
		return nil, err
	}
	var held *Decision
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		var err error
		held, err = within.split(ctx, subject, decisionID, rows, because)
		return err
	})
	return held, err
}

func (s *Store) split(ctx context.Context, subject access.Subject, decisionID int64,
	rows []int64, because string) (*Decision, error) {

	decision, all, err := s.writableRows(ctx, subject, decisionID, mayDecideOn)
	if err != nil {
		return nil, err
	}
	for _, row := range all {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return nil, ErrNotTheirs
		}
	}
	if decision.ProposedBy != subject.ID {
		return nil, refusal.Errorf(
			"only the person who made a decision may hold part of it back; an approver sets rows aside")
	}

	// Every row named has to be one of this decision's, and refusing a stray
	// identifier rather than ignoring it is the same rule setting rows aside
	// holds: a stray identifier is more likely a mistake than a wish.
	named := make(map[int64]bool, len(all))
	waiting := 0
	for _, row := range all {
		named[row.ID] = true
		if row.State == Proposed {
			waiting++
		}
	}
	holding := make(map[int64]bool, len(rows))
	held := make([]int64, 0, len(rows))
	for _, id := range rows {
		if !named[id] {
			return nil, refusal.Errorf("occurrence %d is not part of decision %d", id, decisionID)
		}
		if !holding[id] {
			held = append(held, id)
		}
		holding[id] = true
	}
	if len(holding) >= waiting {
		return nil, refusal.Errorf(
			"that is the whole decision: revise it, or withdraw it, rather than splitting it in two")
	}
	for _, row := range all {
		if holding[row.ID] && row.State != Proposed {
			return nil, refusal.Errorf(
				"occurrence %d is %s, so it is not part of what is still being argued", row.ID, row.State)
		}
	}

	// What makes the rows held back a different decision is the revision that
	// follows.
	now := s.now().Truncate(time.Microsecond)
	return s.intoReturned(ctx, subject, decision, held, because, now, "hold those rows back")
}

// SentBack is what sending a decision back did.
type SentBack struct {
	// Author is whose words were sent back, and who is waiting to hear.
	//
	// One person, because one act is one argument: a revision is keyed on the
	// decision, so a decision rests on exactly one revision and that revision has
	// one writer. It was a set of several, from the shape before the reasoning
	// moved onto the decision.
	Author int64
	// Sent is how many rows went back.
	Sent int
	// DecisionOccurrence is a representative of what went back: the earliest row.
	DecisionOccurrence DecisionOccurrence
	// Undisclosed says at least one row of the decision is about a finding
	// nobody has announced.
	//
	// Not read off DecisionOccurrence above. That row is a representative chosen by
	// identifier for naming the decision, and a decision is one action over many
	// occurrences whose rows need not agree about visibility — so the earliest
	// row being public says nothing about the rest, and what may leave
	// this deployment is decided by the most careful row in the set.
	Undisclosed bool
	// SecurityTesting says at least one row is security testing work, on the same terms.
	SecurityTesting bool
}

// SendBackDecision asks the author for more before agreeing to any of a decision.
//
// Every waiting row leaves the queue together and comes back together when the
// author revises, because they are one argument: sending back half of it
// leaves an approver agreeing to words the author is about to change. As a
// set: one comment inserted per row from a select, one update.
func (s *Store) SendBackDecision(ctx context.Context, subject access.Subject, decisionID int64,
	because string) (*SentBack, error) {

	if strings.TrimSpace(because) == "" {
		return nil, refusal.Errorf("say what needs to change: sending something back without a " +
			"reason is a round trip nobody learns from")
	}
	if err := markdown.Check(because); err != nil {
		return nil, err
	}
	var result *SentBack
	err := s.writing(ctx, func(ctx context.Context, within *Store, tx bun.Tx) error {
		result = &SentBack{}
		decision, rows, err := within.writableRows(ctx, subject, decisionID, mayApproveOn)
		if err != nil {
			return err
		}
		// Whose words, asked once: one act is one argument, and the decision
		// carries it.
		author, err := within.authorOf(ctx, *decision)
		if err != nil {
			return err
		}
		if author == subject.ID {
			return refusal.Errorf("that is your own decision to revise, not one to send back")
		}
		result.Author = author
		var ids []int64
		for _, row := range rows {
			if row.State != Proposed || row.SentBackAt != nil {
				continue
			}
			if len(ids) == 0 {
				result.DecisionOccurrence = row
			}
			// Anything in this decision undisclosed, which
			// decides what may be said about it outside the
			// application. Any row is enough: a decision is one
			// action over many occurrences and its rows need not agree,
			// so the representative row above answers for the
			// decision's identity and not for this.
			if row.Visibility != access.Public {
				result.Undisclosed = true
			}
			if row.Visibility == access.SecurityTesting {
				result.SecurityTesting = true
			}
			ids = append(ids, row.ID)
		}
		if len(ids) == 0 {
			return refusal.Errorf("nothing in that decision is waiting on anybody")
		}
		now := s.now().Truncate(time.Microsecond)
		// The reason travels as a comment on the decision, because that is what
		// it is: the author needs the words, and a reason recorded anywhere
		// else is one nobody reads.
		if err := within.sayOn(ctx, subject, decisionID, because, now); err != nil {
			return err
		}
		marked, err := tx.NewUpdate().Model((*DecisionOccurrence)(nil)).
			Set(`"sent_back_at" = ?`, now).
			Where(`"id" IN (?)`, bun.List(ids)).Where(`"state" = ?`, Proposed).Exec(ctx)
		if err != nil {
			return fmt.Errorf("record that this was sent back: %w", err)
		}
		n, err := database.Affected(marked)
		if err != nil {
			return fmt.Errorf("record that this was sent back: %w", err)
		}
		if n != int64(len(ids)) {
			return refusal.Errorf("the decision changed while it was being sent back; read it again")
		}
		result.Sent = len(ids)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// decisionRows reads a decision and every row in it, under a rule about what
// the subject may do with them.
//
// The rule is asked of every row, not of the first: a decision spans whatever one
// action wrote, and a person who may act on some of it and not the rest is
// refused the whole rather than handed the part — acting on a decision is acting
// on the argument, which does not come in halves. A decision they may reach none
// of answers as one that is not there, like everything else here.
//
// The rule is asked of each row's product, issue and visibility, so a rule
// that honors a case grant can: somebody brought into one issue reads and
// argues the decisions about it.
func (s *Store) decisionRows(ctx context.Context, subject access.Subject, decisionID int64,
	allowed func(access.Subject, int64, int64, access.Visibility) bool) (*Decision, []DecisionOccurrence, error) {
	return s.decisionRowsAs(ctx, subject, decisionID, allowed, false)
}

// decisionRowsAs is decisionRows, widened where widen is set as readableDecisionRows
// says.
func (s *Store) decisionRowsAs(ctx context.Context, subject access.Subject, decisionID int64,
	allowed func(access.Subject, int64, int64, access.Visibility) bool, widen bool) (*Decision, []DecisionOccurrence, error) {

	decision := new(Decision)
	if err := s.db.NewSelect().Model(decision).Where(`"id" = ?`, decisionID).Scan(ctx); err != nil {
		return nil, nil, database.FromRead(err, ErrNotTheirs, fmt.Sprintf("read decision %d", decisionID))
	}
	var rows []DecisionOccurrence
	if err := s.db.NewSelect().Model(&rows).Relation("Decision").
		Where(`"de"."decision_id" = ?`, decisionID).Order("de.id ASC").Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("read what that decision covers: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil, ErrNotTheirs
	}
	var refused []int64
	for _, row := range rows {
		if !allowed(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			refused = append(refused, row.ID)
		}
	}
	if len(refused) > 0 && !widen {
		return nil, nil, ErrNotTheirs
	}
	if len(refused) > 0 {
		included, err := s.readsIncluded(ctx, subject, refused)
		if err != nil {
			return nil, nil, err
		}
		for _, id := range refused {
			if !included[id] {
				return nil, nil, ErrNotTheirs
			}
		}
	}
	return decision, rows, nil
}

// readableDecisionRows is decisionRows for a read: a row the subject reads only as
// one of the flaw's readers of a code finding included in its case is read as well.
func (s *Store) readableDecisionRows(ctx context.Context, subject access.Subject, decisionID int64) (*Decision, []DecisionOccurrence, error) {
	return s.decisionRowsAs(ctx, subject, decisionID, readableOn, true)
}

// readsIncluded is which of these rows the subject reads as one of the
// flaw's readers of a code finding included in its case (orIncluded).
func (s *Store) readsIncluded(ctx context.Context, subject access.Subject, occurrenceIDs []int64) (map[int64]bool, error) {
	out := map[int64]bool{}
	where, args := orIncluded(subject, "1 = 0", nil, `"de"."product_id"`, `"de"."visibility"`, `"de"."occurrence_identity"`)
	if where == "1 = 0" || len(occurrenceIDs) == 0 {
		return out, nil
	}
	var ids []int64
	if err := s.db.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).ColumnExpr(`"de"."id"`).
		Where(`"de"."id" IN (?)`, bun.List(occurrenceIDs)).
		Where(where, args...).
		Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("read which decision occurrences are at an included code finding: %w", err)
	}
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// ErrCodeFindingRecordedAsFlaw refuses a decision about a code finding recorded as a flaw, and a
// change to one already made: the flaw is judged instead.
var ErrCodeFindingRecordedAsFlaw = refusal.New("that code finding was recorded as a flaw, which is judged instead")

// notRecordedAsFlaw refuses a write to a decision about a code finding recorded as a flaw.
// Asked inside the transaction writing it, of every row the decision covers.
func (s *Store) notRecordedAsFlaw(ctx context.Context, decisionID int64) error {
	handed, err := s.recordedAsFlaw(ctx, []int64{decisionID})
	if err != nil {
		return err
	}
	if handed[decisionID] {
		return ErrCodeFindingRecordedAsFlaw
	}
	return nil
}

// recordedAsFlaw is which of these decisions are about a code finding recorded as a flaw:
// a row of the decision filed under an analyzer's rule at an occurrence recorded as a flaw.
func (s *Store) recordedAsFlaw(ctx context.Context, decisionIDs []int64) (map[int64]bool, error) {
	out := map[int64]bool{}
	if err := database.IDsInBatches(ctx, decisionIDs, func(ctx context.Context, batch []int64) error {
		var some []int64
		if err := s.db.NewSelect().TableExpr(`"decision_occurrence" AS "de"`).
			Join(`JOIN "vulnerability" AS "rv" ON "rv"."id" = "de"."vulnerability_id"`).
			Join(`JOIN "code_finding_flaw" AS "lh" ON "lh"."product_id" = "de"."product_id"
				AND "lh"."occurrence_identity" = "de"."occurrence_identity"`).
			ColumnExpr(`DISTINCT "de"."decision_id"`).
			Where(`"de"."decision_id" IN (?)`, bun.List(batch)).
			Where(`"rv"."kind" = ?`, string(kind.Rule)).
			Scan(ctx, &some); err != nil {
			return err
		}
		for _, id := range some {
			out[id] = true
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("read which decisions are about a code finding recorded as a flaw: %w", err)
	}
	return out, nil
}

// writableRows is decisionRows for a write, which a decision about a code finding recorded as a flaw
// as a flaw is refused.
//
// The decision is restamped from the stamp it was read with, after the flaw record
// is asked about. A flaw record restamps the decision it rests on the same way, so
// of a write and a flaw record committing at once one matches nothing, and is
// taken again to find the other: the read of the flaw record alone is a plain
// read, and answers from before a flaw record that has not committed.
func (s *Store) writableRows(ctx context.Context, subject access.Subject, decisionID int64,
	allowed func(access.Subject, int64, int64, access.Visibility) bool) (*Decision, []DecisionOccurrence, error) {

	decision, rows, err := s.decisionRows(ctx, subject, decisionID, allowed)
	if err != nil {
		return nil, nil, err
	}
	stamps, err := s.stampsOf(ctx, []int64{decisionID})
	if err != nil {
		return nil, nil, err
	}
	if err := s.notRecordedAsFlaw(ctx, decisionID); err != nil {
		return nil, nil, err
	}
	if err := s.restamp(ctx, decisionID, stamps[decisionID]); err != nil {
		return nil, nil, err
	}
	return decision, rows, nil
}

// restamp restamps a decision from the stamp read. Inside a transaction the
// store began, it waits for the transaction's end, so the stamp row is
// locked only after every other statement has run: a writer that locks it
// first holds that lock across reads another transaction's write is waiting
// to finish.
func (s *Store) restamp(ctx context.Context, decisionID int64, read int) error {
	if s.restamps == nil {
		return Restamp(ctx, s.db, decisionID, read)
	}
	if _, held := s.restamps[decisionID]; !held {
		s.restamps[decisionID] = read
	}
	return nil
}

// restampAll restamps every decision the transaction wrote, in the order of
// their identifiers, so two transactions lock them in the same order.
func (s *Store) restampAll(ctx context.Context) error {
	ids := make([]int64, 0, len(s.restamps))
	for id := range s.restamps {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err := Restamp(ctx, s.db, id, s.restamps[id]); err != nil {
			return err
		}
	}
	return nil
}

// decisionStamp is the stamp a decision's writers match on (Restamp).
type decisionStamp struct {
	bun.BaseModel `bun:"table:decision_stamp,alias:cs"`

	DecisionID int64 `bun:"decision_id,pk"`
	Stamp      int   `bun:"stamp,notnull"`
}

// Restamp changes a decision's stamp from the value read, inside the transaction
// that read it. A decision whose stamp another writer changed since matched
// nothing, and the attempt is a lost race the retry helper takes again whole.
//
// The stamp is a row of its own, which no foreign key points at, so nothing
// but another stamp's writer holds its lock. A decision nobody has stamped has no
// row and reads as zero; its first stamp inserts the row, and a duplicate key
// there is another writer's first stamp, the same lost race.
//
// The new value is always another number. MySQL and MariaDB leave unwritten a
// row an update leaves as it was, and a cluster certifies only rows that were
// written, so an update to the value already held lets both writers pass.
func Restamp(ctx context.Context, db bun.IDB, decisionID int64, read int) error {
	doing := fmt.Sprintf("restamp decision %d", decisionID)
	result, err := db.NewUpdate().Model((*decisionStamp)(nil)).
		Set(`"stamp" = ?`, read+1).
		Where(`"decision_id" = ?`, decisionID).
		Where(`"stamp" = ?`, read).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", doing, err)
	}
	if read != 0 {
		return movedAll(result, 1, doing)
	}
	n, err := database.Affected(result)
	if err != nil {
		return fmt.Errorf("%s: %w", doing, err)
	}
	if n == 1 {
		return nil
	}
	if _, err := db.NewInsert().Model(&decisionStamp{DecisionID: decisionID, Stamp: read + 1}).Exec(ctx); err != nil {
		if database.IsDuplicate(err) {
			return fmt.Errorf("%s: %w", doing, database.ErrGoAgain)
		}
		return fmt.Errorf("%s: %w", doing, err)
	}
	return nil
}

// stampsOf is the stamp each of these decisions holds, by decision, as the
// transaction reads it. A decision with no stamp row holds zero, which is what
// the map answers for a decision it has no entry for.
func (s *Store) stampsOf(ctx context.Context, decisionIDs []int64) (map[int64]int, error) {
	out := make(map[int64]int, len(decisionIDs))
	if err := database.IDsInBatches(ctx, decisionIDs, func(ctx context.Context, batch []int64) error {
		var rows []decisionStamp
		if err := s.db.NewSelect().Model(&rows).
			Where(`"cs"."decision_id" IN (?)`, bun.List(batch)).Scan(ctx); err != nil {
			return err
		}
		for _, row := range rows {
			out[row.DecisionID] = row.Stamp
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("read the decisions' stamps: %w", err)
	}
	return out, nil
}

// movedAll reads an update that matched on what the transaction read. Fewer
// rows than were read means some moved since, which is a lost race for the
// retry helper to take again.
func movedAll(result sql.Result, want int, doing string) error {
	n, err := database.Affected(result)
	if err != nil {
		return fmt.Errorf("%s: %w", doing, err)
	}
	if n != int64(want) {
		return fmt.Errorf("%s: %w", doing, database.ErrGoAgain)
	}
	return nil
}
