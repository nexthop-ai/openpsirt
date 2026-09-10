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
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// Claim is one proposer's action: what an approver reads and agrees to.
//
// A judgment about a finding writes one decision per place, and a judgment
// about many issues writes one per issue and per place. Those rows stay that
// fine, because each is keyed and lapses on its own. What a second person
// reads is the action — one argument, with its reach — and the queue,
// approval, sending back and undoing all work on that rather than on rows.
type Claim struct {
	bun.BaseModel `bun:"table:claim,alias:cl"`

	ID         int64     `bun:"id,pk,autoincrement"`
	Kind       ClaimKind `bun:"kind,notnull"`
	ProposedBy int64     `bun:"proposed_by,notnull"`
	ProposedAt time.Time `bun:"proposed_at,notnull"`
	// DerivedFrom is the claim this one came from: the approved claim an
	// extension carries to a new issue, or the claim an approver set some rows
	// aside from when agreeing to the rest.
	DerivedFrom *int64 `bun:"derived_from"`
	// SelectedBy is how a bulk set was narrowed. Held on the claim as well as
	// on its rows, so a claim whose rows were all set aside still says how it
	// was found.
	SelectedBy *string `bun:"selected_by"`
	// What the claim says, held once because one act is one argument.
	//
	// These were on the row. A judgment reaching forty-four places was
	// forty-four copies of one sentence, each revisable on its own — so
	// revising one returned that row to the queue and left the other
	// forty-three saying the old thing while the claim read as agreed. Every
	// one of them was constant across every row of every claim in the measured
	// deployment, and nothing has ever produced a claim whose rows differ.
	Outcome Outcome `bun:"outcome,notnull"`
	// Justification is one of the recognized reasons, for the outcome that
	// claims something does not apply — where which reason it is *is* the
	// claim.
	Justification *string `bun:"justification"`
	// Mitigation is what actually stops it, where the claim is that something
	// already does. Required with that justification and meaningless with any
	// other.
	Mitigation *string `bun:"mitigation"`
	// DeferredUntil is when somebody will look again, for the one outcome that
	// expires on a date rather than on the code changing.
	DeferredUntil *time.Time `bun:"deferred_until"`
	// FixedVersion is the package version whoever packages this states the fix
	// arrived in. Required for the outcome that claims the fix is already here
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
	// one revision rather than at the claim, so this moving is exactly what
	// withdraws every approval given for what it used to say.
	RevisionID *int64 `bun:"revision_id"`
	// Elsewhere is where this is being argued about or worked on outside
	// here: a ticket, a thread, a change. Stored and never fetched — a
	// link has no egress at all, which is what makes it available without
	// a deployment first deciding to let anything out.
	Elsewhere string `bun:"elsewhere"`
}

// PointAt records where a claim's work is happening.
//
// Anybody who may argue about the claim may set it, which is the same right
// that made the claim: a link is a note about where the conversation is, not a
// judgment, and needing a second person for it would leave it unset.
//
// Sent empty it is cleared, because a stale link is worse than none — it sends
// somebody to a ticket that closed for a different reason.
func (s *Store) PointAt(ctx context.Context, subject access.Subject, claimID int64,
	where string) error {

	// Read as what they may see, then checked row by row for what they may
	// argue about. The two are asked separately because the second
	// question names the issue: somebody brought into one case may argue
	// about it , and a check that only knew the product would refuse them.
	_, rows, err := s.claimRows(ctx, subject, claimID, readable)
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
	if _, err := s.db.NewUpdate().Model((*Claim)(nil)).
		Set("elsewhere = ?", where).
		Where("id = ?", claimID).Exec(ctx); err != nil {
		return fmt.Errorf("record where the work is: %w", err)
	}
	return nil
}

// argument is what this claim says, in the shape a new claim is recorded from.
//
// Used where a claim is split rather than re-argued: an approver setting rows
// aside is saying "not these", not "something else about these", so the rows
// that move carry the argument they were made under.
func (c Claim) argument() Proposal {
	p := Proposal{
		Outcome:       c.Outcome,
		DeferredUntil: c.DeferredUntil,
		CommittedTo:   c.CommittedTo,
		Mitigation:    orEmpty(c.Mitigation),
		FixedVersion:  orEmpty(c.FixedVersion),
		UpgradeTo:     orEmpty(c.UpgradeTo),
	}
	if c.Justification != nil {
		p.Justification = Justification(*c.Justification)
	}
	return p
}

// ClaimKind is what sort of action a claim was.
type ClaimKind string

const (
	// FindingClaim is one judgment about one issue in one component,
	// covering the places it sits at. A re-affirmation is one too.
	FindingClaim ClaimKind = "finding"
	// TogetherClaim is one judgment about many issues at one component.
	TogetherClaim ClaimKind = "together"
	// ExtensionClaim carries an approved claim to a new issue at the same
	// component under the same consumer, with the same justification.
	ExtensionClaim ClaimKind = "extension"
	// ReturnedClaim holds the rows an approver set aside from a claim they
	// agreed the rest of. It goes back to whoever proposed them.
	ReturnedClaim ClaimKind = "returned"
)

// newClaim records an action and what it argues, inside whatever transaction is
// writing its rows.
//
// The argument comes from a proposal because the two are one thing: a claim
// with no outcome is not something a second person can agree to, and the rows
// underneath carry where it applies rather than what it says.
func (s *Store) newClaim(ctx context.Context, kind ClaimKind, by int64, derivedFrom *int64,
	selectedBy string, p Proposal) (*Claim, error) {

	claim := &Claim{
		Kind: kind, ProposedBy: by, ProposedAt: s.now().Truncate(time.Microsecond),
		DerivedFrom:   derivedFrom,
		Outcome:       p.Outcome,
		DeferredUntil: p.DeferredUntil,
		CommittedTo:   p.CommittedTo,
	}
	if strings.TrimSpace(selectedBy) != "" {
		how := selectedBy
		claim.SelectedBy = &how
	}
	if strings.TrimSpace(p.Mitigation) != "" {
		named := strings.TrimSpace(p.Mitigation)
		claim.Mitigation = &named
	}
	// The version an upgrade moves to, carried on the claim rather than in a
	// record beside it, so what somebody decided and what the release is
	// waiting on cannot come to disagree.
	if p.Outcome == UpgradeNeeded && strings.TrimSpace(p.UpgradeTo) != "" {
		moving := strings.TrimSpace(p.UpgradeTo)
		claim.UpgradeTo = &moving
	}
	if p.Outcome == NotApplicable {
		stated := string(p.Justification)
		claim.Justification = &stated
	}
	if p.Outcome == AlreadyFixed {
		// Read through the same normalization as every other version here, so
		// that a value stored with surrounding space and one typed without it
		// do not read as two different claims.
		arrived := version(p.FixedVersion)
		claim.FixedVersion = &arrived
	}
	if _, err := s.db.NewInsert().Model(claim).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record a claim: %w", err)
	}
	// The reasoning, written with the claim rather than with its rows. The two
	// go together: a claim with no reasoning is not something a second person
	// can agree to, and leaving it to a later write is how something reaches
	// the queue with nothing in it to review.
	revision := &Revision{
		ClaimID: claim.ID, Ordinal: 1,
		Body: p.Reasoning, WrittenBy: by, WrittenAt: claim.ProposedAt,
	}
	if _, err := s.db.NewInsert().Model(revision).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record the reasoning: %w", err)
	}
	if _, err := s.db.NewUpdate().Model((*Claim)(nil)).
		Set("revision_id = ?", revision.ID).
		Where("id = ?", claim.ID).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record the reasoning: %w", err)
	}
	claim.RevisionID = &revision.ID
	if err := noting(ctx, s.db, p.Reasoning, claim.ProposedAt); err != nil {
		return nil, err
	}
	return claim, nil
}

// ErrNotExtendable is returned when a claim cannot be carried to a new issue.
var ErrNotExtendable = errors.New("that claim cannot be extended")

// Extend records the same judgment an approved claim made, against a new issue
// at the same places.
//
// The everyday case rather than the rare one: every nightly scan adds issues
// to components that already carry agreed claims — a new flaw in a kernel
// driver the image does not build — and each arrived as a blank decision. An
// extension is a claim of its own, recorded as derived from the one it
// carries, and it needs a second person like any other dismissal: the approver
// is told the argument was read once already, not that it was agreed to twice
// .
//
// Everything it turns on is read inside the transaction that writes: whether
// the source is approved, and what it was a claim about.
func (s *Store) Extend(ctx context.Context, subject access.Subject, from int64,
	proposals []Proposal, cap int) ([]*Decision, error) {

	if len(proposals) == 0 {
		return nil, nil
	}
	if err := allowed(subject, proposals, cap, s.now()); err != nil {
		return nil, err
	}

	db, ok := s.db.(*bun.DB)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}

	var recorded []*Decision
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		recorded = recorded[:0]

		source, err := within.extendable(ctx, subject, from, proposals)
		if err != nil {
			return err
		}
		claim, err := within.newClaim(ctx, ExtensionClaim, subject.ID, &source.ID, "", proposals[0])
		if err != nil {
			return err
		}
		recorded, err = within.proposeAll(ctx, claim, proposals)
		return err
	})
	if err != nil {
		if errors.Is(err, ErrAlreadyDecided) {
			for _, p := range proposals {
				if standing, found := s.liveAt(ctx, liveKeyFor(p.Place)); found {
					return nil, fmt.Errorf(
						"%w: decision %d is already %s at one of these places — revise that one "+
							"rather than recording a second claim about the same code",
						ErrAlreadyDecided, standing.ID, standing.State)
				}
			}
		}
		return nil, err
	}
	return recorded, nil
}

// extendable reads the claim being carried and checks it can be.
//
// Three things have to hold, and each is a claim the extension would otherwise
// be making on the source's behalf: the source is agreed to — every row of it
// approved, none withdrawn or lapsed — so an extension never carries an
// argument nobody agreed with; the new rows sit at places the source sits at,
// in the same product, because "the same argument" is about the same code
// under the same consumer; and the outcome and justification are the source's,
// because a different conclusion is a different claim.
func (s *Store) extendable(ctx context.Context, subject access.Subject, from int64,
	proposals []Proposal) (*Claim, error) {

	source := new(Claim)
	if err := s.db.NewSelect().Model(source).Where("id = ?", from).Scan(ctx); err != nil {
		return nil, ErrNotTheirs
	}
	var rows []Decision
	if err := s.db.NewSelect().Model(&rows).Where("claim_id = ?", from).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what that claim covers: %w", err)
	}
	if len(rows) == 0 {
		return nil, ErrNotTheirs
	}
	places := map[string]bool{}
	for _, row := range rows {
		if !readable(subject, row.ProductID, row.Visibility) {
			return nil, ErrNotTheirs
		}
		if row.State != Approved {
			return nil, fmt.Errorf("%w: it is %s, and only an approved claim carries", ErrNotExtendable, row.State)
		}
		places[row.PlaceIdentity] = true
	}
	first := rows[0]
	for _, p := range proposals {
		if p.Place.ProductID != first.ProductID {
			return nil, fmt.Errorf("%w: it is about a different product", ErrNotExtendable)
		}
		if !places[p.Place.PlaceIdentity] {
			return nil, fmt.Errorf("%w: it is about a different component or consumer", ErrNotExtendable)
		}
		if p.Place.VulnerabilityID == first.VulnerabilityID {
			return nil, fmt.Errorf("%w: it already covers this issue", ErrNotExtendable)
		}
		if p.Outcome != source.Outcome || string(p.Justification) != orEmpty(source.Justification) {
			return nil, fmt.Errorf("%w: an extension keeps the outcome and justification it carries", ErrNotExtendable)
		}
	}
	return source, nil
}

// ClaimApproved is what agreeing to a claim did.
type ClaimApproved struct {
	// Approved is how many decisions were agreed to.
	Approved int
	// Returned is the claim the rows set aside went into, where any were.
	Returned *Claim
	// ReturnedIn is the product those rows are in. A claim carries no
	// product of its own — it is one argument over many decisions, and each
	// decision holds the product — so it is read off the rows that moved,
	// for whoever has to say what the telling about them is about.
	ReturnedIn int64
}

// ApproveClaim records a second person agreeing to a claim: every decision in
// it, as one action, under the same rules each decision is approved under.
//
// Rows may be set aside. An approver of a bulk claim who has found the handful
// of rows that do not look like the rest should not have to choose between
// refusing everything and agreeing to everything: the rest is approved as one
// claim, and the rows set aside go back to the proposer as a claim of their
// own, carrying the reason the way sending back does.
func (s *Store) ApproveClaim(ctx context.Context, subject access.Subject, claimID int64,
	batch string, except []int64, because string) (*ClaimApproved, error) {

	if len(except) > 0 {
		if strings.TrimSpace(because) == "" {
			return nil, fmt.Errorf("say why those are set aside: rows returned with no reason " +
				"are a round trip nobody learns from")
		}
		if err := markdown.Check(because); err != nil {
			return nil, err
		}
	}
	db, ok := s.db.(*bun.DB)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}

	var result *ClaimApproved
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		var err error
		result, err = within.approveClaim(ctx, subject, claimID, batch, except, because)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) approveClaim(ctx context.Context, subject access.Subject, claimID int64,
	batch string, except []int64, because string) (*ClaimApproved, error) {

	claim, rows, err := s.claimRows(ctx, subject, claimID, mayApprove)
	if err != nil {
		return nil, err
	}
	aside := make(map[int64]bool, len(except))
	for _, id := range except {
		aside[id] = true
	}
	// Every row named as set aside has to be one of this claim's. A stray
	// identifier is more likely a mistake than a wish, and silently ignoring
	// it would approve a row somebody meant to hold back.
	named := make(map[int64]bool, len(rows))
	for _, row := range rows {
		named[row.ID] = true
	}
	for id := range aside {
		if !named[id] {
			return nil, fmt.Errorf("decision %d is not part of claim %d", id, claimID)
		}
	}
	if claim.RevisionID == nil {
		return nil, ErrNothingToApprove
	}
	// Compared against whoever wrote the words being agreed to, not only
	// against whoever proposed the claim. An approval names one revision, so
	// the control is about the text — and anybody who may triage can revise,
	// which made "did you propose this" the wrong question: revise somebody
	// else's claim in your own words and you could then approve your own.
	author, err := s.authorOf(ctx, *claim)
	if err != nil {
		return nil, err
	}
	samePerson := author == subject.ID || claim.ProposedBy == subject.ID

	var approving, returning []int64
	var returnedIn int64
	for _, row := range rows {
		if row.State != Proposed {
			continue
		}
		if aside[row.ID] {
			// Setting rows aside is an approver's act as much as agreeing
			// is — the rest of the claim is approved in the same action — so
			// the proposer naming their own rows as set aside would be acting
			// on their own claim.
			if samePerson {
				return nil, ErrSamePerson
			}
			returning = append(returning, row.ID)
			returnedIn = row.ProductID
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
	result := &ClaimApproved{}
	if len(approving) > 0 {
		if err := s.agree(ctx, subject, *claim, approving, batch, now); err != nil {
			return nil, err
		}
		result.Approved = len(approving)
	}

	if len(returning) > 0 {
		// The same argument, in a claim of its own: what an approver set
		// aside is these rows, not a different judgment about them. The
		// reasoning travels with it, because a claim with none is one nobody
		// can be asked to agree to.
		carried := claim.argument()
		if carried.Reasoning, err = s.reasoningOn(ctx, *claim); err != nil {
			return nil, err
		}
		returned, err := s.newClaim(ctx, ReturnedClaim, claim.ProposedBy, &claim.ID,
			orEmpty(claim.SelectedBy), carried)
		if err != nil {
			return nil, err
		}
		if _, err := s.db.NewUpdate().Model((*Decision)(nil)).
			Set("claim_id = ?", returned.ID).
			Set("sent_back_at = ?", now).
			Where("id IN (?)", bun.List(returning)).Exec(ctx); err != nil {
			return nil, fmt.Errorf("set rows aside: %w", err)
		}
		// The reason travels as a comment on the claim the rows went into, the
		// way sending back records it: the author needs the words, and a
		// reason kept anywhere else is one nobody reads.
		if err := s.sayOn(ctx, subject, returned.ID, because, now); err != nil {
			return nil, err
		}
		result.Returned = returned
		result.ReturnedIn = returnedIn
	}
	return result, nil
}

// agree records one person agreeing to a claim, and moves the rows it covers.
//
// One approval row, because one act is one argument: an approver reads the
// words once and agrees to them once, and a row per place was a copy of that
// agreement that could go on standing after the words changed.
//
// **The revision-bound control is the condition on the update.** The approval
// names the revision it was given for, and the rows move only while that is
// still the reasoning the claim rests on. A revision landing in between leaves
// them unmoved, the matched count falls short, and the whole claim is refused
// rather than half of it agreed to.
func (s *Store) agree(ctx context.Context, subject access.Subject, claim Claim, ids []int64,
	batch string, now time.Time) error {

	covered, err := s.covering(ctx, subject, ids)
	if err != nil {
		return err
	}
	approval := &Approval{
		ClaimID: claim.ID, RevisionID: *claim.RevisionID,
		ApprovedBy: subject.ID, ApprovedAt: now, Covered: &covered,
	}
	if strings.TrimSpace(batch) != "" {
		approval.Batch = &batch
	}
	if _, err := s.db.NewInsert().Model(approval).Exec(ctx); err != nil {
		return fmt.Errorf("record an approval: %w", err)
	}

	moved, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set("state = ?", Approved).
		Where("id IN (?)", bun.List(ids)).
		Where("state = ?", Proposed).
		Where(`EXISTS (SELECT 1 FROM "claim" AS ac WHERE ac.id = ? AND ac.revision_id = ?)`,
			claim.ID, *claim.RevisionID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("record an approval: %w", err)
	}
	if n, err := moved.RowsAffected(); err == nil && n != int64(len(ids)) {
		return fmt.Errorf("the reasoning changed while this was being agreed to; read it again")
	}
	return nil
}

// sayOn records one comment on a claim.
func (s *Store) sayOn(ctx context.Context, subject access.Subject, claimID int64, body string,
	now time.Time) error {

	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("a comment has to say something")
	}
	if err := markdown.Check(body); err != nil {
		return err
	}
	comment := &Comment{ClaimID: claimID, Body: body, WrittenBy: subject.ID, WrittenAt: now}
	if _, err := s.db.NewInsert().Model(comment).Exec(ctx); err != nil {
		return fmt.Errorf("record a comment: %w", err)
	}
	return noting(ctx, s.db, body, now)
}

// reasoningOn is the words a claim currently rests on.
func (s *Store) reasoningOn(ctx context.Context, claim Claim) (string, error) {
	if claim.RevisionID == nil {
		return "", ErrNothingToApprove
	}
	revision := new(Revision)
	if err := s.db.NewSelect().Model(revision).
		Where("id = ?", *claim.RevisionID).Scan(ctx); err != nil {
		return "", fmt.Errorf("read what it says: %w", err)
	}
	return revision.Body, nil
}

// Split holds back part of a claim the proposer no longer wants to argue as one.
//
// **The approver's side of this already existed and the proposer's did not.**
// An approver reading a bulk claim may agree to most of it and set some rows
// aside; whoever wrote it could only withdraw the whole thing and start again,
// so "this holds for most of them but not those four" was unavailable to the
// person best placed to say it — and the same outliers that help an approver
// choose a subset were shown only to the approver.
//
// The same mechanism rather than a second one: the rows named move into a claim
// of their own, derived from this one, carrying the argument they were made
// under, with the reason recorded as a comment and the rows marked as sitting
// with their author. What happens next is a revision, which is the act that
// gives them an argument of their own.
//
// **A proposer's act, as setting rows aside is an approver's.** Each is refused
// to the other: an approver holding some of a claim back is agreeing to the
// rest in the same action, and a proposer doing that would be approving their
// own claim.
func (s *Store) Split(ctx context.Context, subject access.Subject, claimID int64,
	rows []int64, because string) (*Claim, error) {

	if len(rows) == 0 {
		return nil, fmt.Errorf("say which rows are being held back")
	}
	if strings.TrimSpace(because) == "" {
		return nil, fmt.Errorf("say why these are being held back: a subset with no reason " +
			"is a claim nobody can read afterwards")
	}
	if err := markdown.Check(because); err != nil {
		return nil, err
	}
	db, ok := s.db.(*bun.DB)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}
	var held *Claim
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		var err error
		held, err = within.split(ctx, subject, claimID, rows, because)
		return err
	})
	return held, err
}

func (s *Store) split(ctx context.Context, subject access.Subject, claimID int64,
	rows []int64, because string) (*Claim, error) {

	claim, all, err := s.claimRows(ctx, subject, claimID, mayDecide)
	if err != nil {
		return nil, err
	}
	for _, row := range all {
		if !mayDecideOn(subject, row.ProductID, row.VulnerabilityID, row.Visibility) {
			return nil, ErrNotTheirs
		}
	}
	if claim.ProposedBy != subject.ID {
		return nil, fmt.Errorf(
			"only the person who made a claim may hold part of it back; an approver sets rows aside")
	}

	// Every row named has to be one of this claim's, and refusing a stray
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
	for _, id := range rows {
		if !named[id] {
			return nil, fmt.Errorf("decision %d is not part of claim %d", id, claimID)
		}
		holding[id] = true
	}
	if len(holding) >= waiting {
		return nil, fmt.Errorf(
			"that is the whole claim: revise it, or withdraw it, rather than splitting it in two")
	}
	for _, row := range all {
		if holding[row.ID] && row.State != Proposed {
			return nil, fmt.Errorf(
				"decision %d is %s, so it is not part of what is still being argued", row.ID, row.State)
		}
	}

	// The same argument, in a claim of its own. The reasoning travels with it,
	// because a claim with none is one nobody can be asked to agree to — and
	// what makes it a different claim is the revision that follows.
	carried := claim.argument()
	if carried.Reasoning, err = s.reasoningOn(ctx, *claim); err != nil {
		return nil, err
	}
	held, err := s.newClaim(ctx, ReturnedClaim, claim.ProposedBy, &claim.ID,
		orEmpty(claim.SelectedBy), carried)
	if err != nil {
		return nil, err
	}
	now := s.now().Truncate(time.Microsecond)
	if _, err := s.db.NewUpdate().Model((*Decision)(nil)).
		Set("claim_id = ?", held.ID).
		// With their author, which is what they are: they leave the review
		// queue until the argument for them is stated again.
		Set("sent_back_at = ?", now).
		Where("id IN (?)", bun.List(rows)).Exec(ctx); err != nil {
		return nil, fmt.Errorf("hold those rows back: %w", err)
	}
	if err := s.sayOn(ctx, subject, held.ID, because, now); err != nil {
		return nil, err
	}
	return held, nil
}

// SentBack is what sending a claim back did.
type SentBack struct {
	// Authors is everybody whose words were sent back, each once, in the
	// order of the rows. Usually one person; a claim revised row by row can
	// rest on several people's words, and each of them is waiting to hear.
	Authors []int64
	// Sent is how many rows went back.
	Sent int
	// Decision is a representative of what went back: the earliest row.
	Decision Decision
	// Undisclosed says at least one row of the claim is about a finding
	// nobody has announced.
	//
	// Not read off Decision above. That row is a representative chosen by
	// identifier for naming the claim, and a claim is one action over many
	// places whose rows need not agree about visibility — so the earliest
	// row being public says nothing about the rest, and what may leave
	// this deployment is decided by the most careful row in the set.
	Undisclosed bool
}

// SendBackClaim asks the author for more before agreeing to any of a claim.
//
// Every waiting row leaves the queue together and comes back together when the
// author revises, because they are one argument: sending back half of it
// leaves an approver agreeing to words the author is about to change. As a
// set: one comment inserted per row from a select, one update.
func (s *Store) SendBackClaim(ctx context.Context, subject access.Subject, claimID int64,
	because string) (*SentBack, error) {

	if strings.TrimSpace(because) == "" {
		return nil, fmt.Errorf("say what needs to change: sending something back without a " +
			"reason is a round trip nobody learns from")
	}
	if err := markdown.Check(because); err != nil {
		return nil, err
	}
	db, ok := s.db.(*bun.DB)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}
	var result *SentBack
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		within := &Store{db: tx, now: s.now}
		result = &SentBack{}
		claim, rows, err := within.claimRows(ctx, subject, claimID, mayApprove)
		if err != nil {
			return err
		}
		// Whose words, asked once: one act is one argument, and the claim
		// carries it.
		author, err := within.authorOf(ctx, *claim)
		if err != nil {
			return err
		}
		if author == subject.ID {
			return fmt.Errorf("that is your own claim to revise, not one to send back")
		}
		var ids []int64
		told := map[int64]bool{}
		for _, row := range rows {
			if row.State != Proposed || row.SentBackAt != nil {
				continue
			}
			if len(ids) == 0 {
				result.Decision = row
			}
			// Whether anything in this claim is undisclosed, which
			// decides what may be said about it outside the
			// application. Any row is enough: a claim is one
			// action over many places and its rows need not agree,
			// so the representative row above answers for the
			// claim's identity and not for this.
			if row.Visibility == access.Private {
				result.Undisclosed = true
			}
			if author != 0 && !told[author] {
				told[author] = true
				result.Authors = append(result.Authors, author)
			}
			ids = append(ids, row.ID)
		}
		if len(ids) == 0 {
			return fmt.Errorf("nothing in that claim is waiting on anybody")
		}
		now := s.now().Truncate(time.Microsecond)
		// The reason travels as a comment on the claim, because that is what
		// it is: the author needs the words, and a reason recorded anywhere
		// else is one nobody reads.
		if err := within.sayOn(ctx, subject, claimID, because, now); err != nil {
			return err
		}
		marked, err := tx.NewUpdate().Model((*Decision)(nil)).
			Set("sent_back_at = ?", now).
			Where("id IN (?)", bun.List(ids)).Where("state = ?", Proposed).Exec(ctx)
		if err != nil {
			return fmt.Errorf("record that this was sent back: %w", err)
		}
		if n, err := marked.RowsAffected(); err == nil && n != int64(len(ids)) {
			return fmt.Errorf("the claim changed while it was being sent back; read it again")
		}
		result.Sent = len(ids)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// claimRows reads a claim and every decision in it, under a rule about what
// the subject may do with them.
//
// The rule is asked of every row, not of the first: a claim spans whatever one
// action wrote, and a person who may act on some of it and not the rest is
// refused the whole rather than handed the part — acting on a claim is acting
// on the argument, which does not come in halves. A claim they may reach none
// of answers as one that is not there, like everything else here.
func (s *Store) claimRows(ctx context.Context, subject access.Subject, claimID int64,
	allowed func(access.Subject, int64, access.Visibility) bool) (*Claim, []Decision, error) {

	claim := new(Claim)
	if err := s.db.NewSelect().Model(claim).Where("id = ?", claimID).Scan(ctx); err != nil {
		return nil, nil, ErrNotTheirs
	}
	var rows []Decision
	if err := s.db.NewSelect().Model(&rows).Relation("Claim").
		Where("de.claim_id = ?", claimID).Order("de.id ASC").Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("read what that claim covers: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil, ErrNotTheirs
	}
	for _, row := range rows {
		if !allowed(subject, row.ProductID, row.Visibility) {
			return nil, nil, ErrNotTheirs
		}
	}
	return claim, rows, nil
}
