package advisory

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

// ErrNotAgreed says nobody has agreed to what the advisory says as it stands.
var ErrNotAgreed = errors.New(
	"an advisory goes out once a second person has agreed to what it says")

// ErrSamePerson says the one person cannot be both halves of the control.
//
// A one-person deployment therefore cannot issue an advisory. That is the
// control working rather than a gap in it, and it is better said plainly than
// quietly relaxed.
var ErrSamePerson = errors.New(
	"whoever wrote what an advisory says may not be the person who agrees to it")

// ErrAlreadyAgreed says this person has already agreed to this edition.
var ErrAlreadyAgreed = errors.New("you have already agreed to what this advisory says")

// ErrNothingAgreed says there is no agreement standing to take back.
var ErrNothingAgreed = errors.New("no agreement is standing on what this advisory says")

// Edition is what an advisory says at a point.
//
// An approval names an edition rather than the advisory. The whole value of a
// second pair of eyes is that they read particular words; an agreement that
// floated free of them would still be standing after somebody rewrote them,
// and nothing would report that.
//
// What it holds is the title, which is the prose this deployment chose. The
// rest of the document is assembled from the issues it covers, and which
// issues those are at any moment is recoverable from when each was added and
// taken off — so the edition marks the moment rather than copying the answer.
type Edition struct {
	bun.BaseModel `bun:"table:advisory_edition,alias:ae"`

	ID         int64 `bun:"id,pk,autoincrement"`
	AdvisoryID int64 `bun:"advisory_id,notnull"`
	// Ordinal is which edition this is, counting from one. It is what a
	// reader of the record follows to find out what somebody agreed to.
	Ordinal   int       `bun:"ordinal,notnull"`
	Title     string    `bun:"title"`
	WrittenBy int64     `bun:"written_by,notnull"`
	WrittenAt time.Time `bun:"written_at,notnull"`
}

// Approval is a second person agreeing to one edition of an advisory.
//
// Kept rather than reduced to a flag, because an approval that was later
// withdrawn is part of the record: it says a second person did once agree, and
// to which edition.
type Approval struct {
	bun.BaseModel `bun:"table:advisory_approval,alias:aa"`

	ID          int64      `bun:"id,pk,autoincrement"`
	AdvisoryID  int64      `bun:"advisory_id,notnull"`
	EditionID   int64      `bun:"edition_id,notnull"`
	ApprovedBy  int64      `bun:"approved_by,notnull"`
	ApprovedAt  time.Time  `bun:"approved_at,notnull"`
	WithdrawnAt *time.Time `bun:"withdrawn_at"`
	// WithdrawnBy is who took the agreement back, which is not who gave it.
	// An edit takes back every agreement standing on what it replaced, and
	// the person who edited is the person who took it back.
	WithdrawnBy *int64 `bun:"withdrawn_by"`
}

// Retitle gives the advisory a new title, as a new edition.
//
// Taking back the agreements standing on the old title is the point rather
// than a side effect. A second person agreed to particular words; different
// words are a document nobody has agreed to, and letting the agreement carry
// over would defeat the control silently — which is worse than not having it,
// because the record would say two people had read something only one of them
// had.
//
// It answers with what the advisory covers as well, because the caller that
// retitles one goes on to show it and the read is the same read.
func (s *Store) Retitle(ctx context.Context, subject access.Subject,
	identifier, title string) (*Advisory, []Covered, error) {

	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return nil, nil, err
	}
	if err := s.mayWrite(ctx, subject, row, "retitle an advisory"); err != nil {
		return nil, nil, err
	}
	title = strings.TrimSpace(title)
	// The same submission policy a justification goes through, before the
	// text is stored. It is our own prose and it reaches the published
	// document's title.
	if err := markdown.Check(title); err != nil {
		return nil, nil, err
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		_, err := openEdition(ctx, tx, row.ID, subject.ID, title, now)
		return err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("retitle an advisory: %w", err)
	}
	row.Title = title
	held, err := s.covers(ctx, row)
	if err != nil {
		return nil, nil, err
	}
	return row, held, nil
}

// openEdition writes the next edition and takes back every agreement standing
// on the one it replaces.
//
// One place, because every act that changes what the document says runs it:
// retitling, naming a flaw, and taking one off. A rule enforced at one of
// three sites is a rule that holds until somebody does their job.
//
// The ordinal is read and used in the same transaction, so two people editing
// at the same moment cannot be handed the same number.
func openEdition(ctx context.Context, tx bun.Tx, advisoryID, who int64,
	title string, now time.Time) (*Edition, error) {

	var highest int
	if err := tx.NewSelect().Model((*Edition)(nil)).
		ColumnExpr("COALESCE(MAX(ordinal), 0)").
		Where("advisory_id = ?", advisoryID).
		Scan(ctx, &highest); err != nil {
		return nil, err
	}
	// Built inside the transaction, because the insert writes the generated
	// identifier back into the model. A retry would otherwise re-insert a
	// model carrying the rolled-back attempt's answer.
	edition := &Edition{
		AdvisoryID: advisoryID, Ordinal: highest + 1,
		Title: title, WrittenBy: who, WrittenAt: now,
	}
	if _, err := tx.NewInsert().Model(edition).Exec(ctx); err != nil {
		return nil, err
	}
	if _, err := tx.NewUpdate().Model((*Advisory)(nil)).
		Set("edition_id = ?", edition.ID).
		Where("id = ?", advisoryID).Exec(ctx); err != nil {
		return nil, err
	}
	if _, err := tx.NewUpdate().Model((*Approval)(nil)).
		Set("withdrawn_at = ?", now).
		Set("withdrawn_by = ?", who).
		Where("advisory_id = ?", advisoryID).
		Where("withdrawn_at IS NULL").Exec(ctx); err != nil {
		return nil, err
	}
	return edition, nil
}

// carryTitle is the title the next edition keeps.
//
// Naming a flaw on an advisory changes what the document says without
// changing what it is called, so the edition it opens carries the title
// forward.
//
// Which edition that is comes from inside the transaction. The advisory moves
// under a retitle, and a retry re-runs this against a database that has moved
// — so a title read before the transaction began describes an edition that
// has been replaced, and carrying it forward would quietly undo the retitle.
func carryTitle(ctx context.Context, tx bun.Tx, advisoryID int64) (string, error) {
	var at Advisory
	if err := tx.NewSelect().Model(&at).
		ColumnExpr(`"ad"."edition_id"`).
		Where("id = ?", advisoryID).Limit(1).Scan(ctx); err != nil {
		return "", err
	}
	if at.EditionID == nil {
		return "", nil
	}
	var edition Edition
	err := tx.NewSelect().Model(&edition).
		Where("id = ?", *at.EditionID).Limit(1).Scan(ctx)
	if err != nil && !database.IsNoRows(err) {
		return "", err
	}
	return edition.Title, nil
}

// Approve records a second person agreeing to what the advisory says.
//
// Against one edition, not against the advisory, for the reason the claim
// approval it is modelled on names: an agreement that floats free of the words
// would still be standing after somebody rewrote them.
//
// The approver is neither the person who wrote the current edition nor the
// person who started the advisory, with no override. Both, because the second
// pair of eyes has to be the second pair: whoever minted an advisory chose the
// name a reader cites it by and, in the ordinary case, the flaws it covers.
func (s *Store) Approve(ctx context.Context, subject access.Subject,
	identifier string) (*Approval, error) {

	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return nil, err
	}
	if err := s.mayWrite(ctx, subject, row, "agree to an advisory"); err != nil {
		return nil, err
	}
	// An advisory covering nothing states nothing, so there is nothing to
	// agree to. Refused here rather than at the document, so the refusal
	// reaches whoever is being asked to read it.
	held, err := s.covers(ctx, row)
	if err != nil {
		return nil, err
	}
	if len(held) == 0 {
		return nil, ErrNothingToSay
	}
	if row.EditionID == nil {
		return nil, ErrNothingToSay
	}
	if row.MintedBy == subject.ID {
		return nil, ErrSamePerson
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	var given *Approval
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		// Read inside the transaction, because the edition the advisory
		// points at is what is being agreed to and it moves under an edit.
		// Read outside, the agreement would name an edition that had already
		// been replaced by the time it was written.
		var at Advisory
		if err := tx.NewSelect().Model(&at).
			Where("id = ?", row.ID).Limit(1).Scan(ctx); err != nil {
			return err
		}
		if at.EditionID == nil {
			return ErrNothingToSay
		}
		var edition Edition
		if err := tx.NewSelect().Model(&edition).
			Where("id = ?", *at.EditionID).Limit(1).Scan(ctx); err != nil {
			return err
		}
		if edition.WrittenBy == subject.ID {
			return ErrSamePerson
		}
		var already int
		if err := tx.NewSelect().Model((*Approval)(nil)).
			ColumnExpr("COUNT(*)").
			Where("edition_id = ?", edition.ID).
			Where("approved_by = ?", subject.ID).
			Where("withdrawn_at IS NULL").
			Scan(ctx, &already); err != nil {
			return err
		}
		if already > 0 {
			return ErrAlreadyAgreed
		}
		given = &Approval{
			AdvisoryID: row.ID, EditionID: edition.ID,
			ApprovedBy: subject.ID, ApprovedAt: now,
		}
		_, err := tx.NewInsert().Model(given).Exec(ctx)
		return err
	})
	switch {
	case errors.Is(err, ErrSamePerson), errors.Is(err, ErrAlreadyAgreed),
		errors.Is(err, ErrNothingToSay):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("agree to an advisory: %w", err)
	}
	return given, nil
}

// Withdraw takes back the agreements standing on what the advisory says.
//
// An explicit act by a person rather than something that happens to an
// advisory. An edit takes an agreement back because the words moved; this is
// somebody saying they no longer agree to words that have not.
//
// It needs no agreement of its own. Taking one back stops a document going
// out, which exposes the question rather than hiding it.
func (s *Store) Withdraw(ctx context.Context, subject access.Subject,
	identifier string) error {

	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return err
	}
	if err := s.mayWrite(ctx, subject, row, "take back an agreement"); err != nil {
		return err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	var taken int64
	err = database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		result, err := tx.NewUpdate().Model((*Approval)(nil)).
			Set("withdrawn_at = ?", now).
			Set("withdrawn_by = ?", subject.ID).
			Where("advisory_id = ?", row.ID).
			Where("withdrawn_at IS NULL").Exec(ctx)
		if err != nil {
			return err
		}
		taken, err = result.RowsAffected()
		return err
	})
	if err != nil {
		return fmt.Errorf("take back an agreement: %w", err)
	}
	if taken == 0 {
		return ErrNothingAgreed
	}
	return nil
}

// Standing is where an advisory is in its life and who agrees to what it says.
type Standing struct {
	// Status is the word the document's tracking carries.
	Status string
	// Agreed is the agreements on the edition the advisory currently points
	// at, oldest first. None is what a document that may not go out looks
	// like.
	Agreed []Approval
}

// Where reports where the advisory stands, without generating its document.
//
// Somebody deciding whether to read it, agree to it or publish it is asking
// before anything is assembled, and assembling a document to find out whether
// it may go out reads every flaw it covers to answer a question about two
// rows.
func (s *Store) Where(ctx context.Context, subject access.Subject,
	identifier string) (*Standing, error) {

	row, err := s.byName(ctx, subject, identifier)
	if err != nil {
		return nil, err
	}
	agreed, err := s.agreed(ctx, row)
	if err != nil {
		return nil, err
	}
	gone, err := s.issuances(ctx, row)
	if err != nil {
		return nil, err
	}
	return &Standing{
		Status: statusOf(len(gone) > 0, len(agreed) > 0), Agreed: agreed,
	}, nil
}

// agreed is the same, for a caller that has already narrowed.
//
// It takes the advisory rather than its identifier for the reason the read of
// what it covers does: the clearance is the argument, and the only things that
// answer with one have narrowed or just minted it.
//
// Two things stop an agreement to what an advisory said before counting as an
// agreement to what it says now, and they are not equally load-bearing. The
// withdrawal an edit performs is what empties this; narrowing to the current
// edition changes no answer while that holds, and is kept because it fails
// the safe way. An edit path that forgot to withdraw would otherwise carry an
// agreement across a rewrite silently, which is the way REQ-24 is defeated
// without anything reporting it.
func (s *Store) agreed(ctx context.Context, row *Advisory) ([]Approval, error) {
	if row.EditionID == nil {
		return nil, nil
	}
	var rows []Approval
	err := s.db.NewSelect().Model(&rows).
		Where("edition_id = ?", *row.EditionID).
		Where("withdrawn_at IS NULL").
		OrderExpr("aa.approved_at ASC, aa.id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who has agreed to it: %w", err)
	}
	return rows, nil
}

// statusOf is where the document is in its life, in the standard's words.
//
// Read from what people did about the document rather than from the embargo.
// The two come apart in both directions: a document about disclosed issues can
// still be unfinished, and one about an embargoed issue can be ready to go.
//
// Every arm is a fact somebody created deliberately. A document nobody has
// published is a draft whatever anybody thinks of it; one that has gone out
// and whose current words a second person agrees to is final; one that has
// gone out and has been edited since is published and being worked on, which
// is the third status and the one that could not be expressed at all while
// this was read from the embargo.
func statusOf(issued, agreed bool) string {
	switch {
	case !issued:
		return "draft"
	case agreed:
		return "final"
	default:
		return "interim"
	}
}

// mayWrite reports whether this subject may change what an advisory says.
//
// The triage role on every product it covers, not on one of them. An advisory
// is read whole or not at all, and what it says about one product is part of
// the same document as what it says about another — so somebody who triages
// one of two products would otherwise retitle a document published about both,
// or agree to it on behalf of a product they only read.
//
// One covering nothing is its minter's alone, which is the rule reading it by
// name applies: byName has already refused anybody else, and the role
// somewhere is what minting asked for.
//
// The refusal is a denial rather than the answer a name nobody minted gets.
// Whoever reaches this has already been handed the advisory by name, so
// telling them it does not exist contradicts the read they just performed.
func (s *Store) mayWrite(ctx context.Context, subject access.Subject, row *Advisory,
	what string) error {

	if subject.Kind != access.Person || subject.ID == 0 {
		return access.Denied(what)
	}
	var products []int64
	err := s.db.NewSelect().
		TableExpr(`"advisory_issue" AS "ac"`).
		ColumnExpr(`DISTINCT ac.product_id`).
		Where("ac.advisory_id = ?", row.ID).
		Where("ac.removed_at IS NULL").
		Scan(ctx, &products)
	if err != nil {
		return fmt.Errorf("read what the advisory covers: %w", err)
	}
	if len(products) == 0 {
		if !subject.HoldsAnywhere(access.PublicTriage, access.PrivateTriage) {
			return access.Denied(what)
		}
		return nil
	}
	for _, id := range products {
		if !triages(subject, id) {
			return access.Denied(what)
		}
	}
	return nil
}
