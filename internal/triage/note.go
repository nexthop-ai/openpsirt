package triage

// Notes on an issue in a product: what somebody wanted whoever decides to
// know, without recording a judgment of their own.

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

// IssueNote is something written about an issue in a product.
//
// Not a comment on a claim, and not a claim. A comment hangs off an argument
// somebody made, and the box for one appears only where a claim already
// exists — so the first person to say anything had to record a judgment in
// order to say it. A note records none.
//
// Keyed on the issue and the product, the way a rating is (REQ-29), because a
// row in the findings list is one issue at one fold and one issue is often
// several rows. A note attached to a row would be written on one of eleven and
// hidden from the other ten.
type IssueNote struct {
	bun.BaseModel `bun:"table:issue_note,alias:nt"`

	ID              int64     `bun:"id,pk,autoincrement"`
	VulnerabilityID int64     `bun:"vulnerability_id,notnull"`
	ProductID       int64     `bun:"product_id,notnull"`
	Body            string    `bun:"body,notnull"`
	WrittenBy       int64     `bun:"written_by,notnull"`
	WrittenAt       time.Time `bun:"written_at,notnull"`
	// EditedAt marks that the author changed it. What it said before is kept
	// too, for the reason a claim comment's is: a note is part of the record
	// that goes public at disclosure, and a record whose earlier text is
	// unrecoverable is readable rather than checkable.
	EditedAt *time.Time `bun:"edited_at"`
}

// WasNoted is what a note said before it was changed.
type WasNoted struct {
	bun.BaseModel `bun:"table:issue_note_revision,alias:ntr"`

	ID         int64     `bun:"id,pk,autoincrement"`
	NoteID     int64     `bun:"note_id,notnull"`
	Ordinal    int       `bun:"ordinal,notnull"`
	Body       string    `bun:"body,notnull"`
	ReplacedAt time.Time `bun:"replaced_at,notnull"`
}

// ErrNoSuchNote is returned where a note is missing or is about an issue in a
// product this subject may not be told about. One error for both, because
// telling them apart is what turns a note identifier into a directory.
var ErrNoSuchNote = errors.New("no note is recorded there")

// NoteOn writes a note about an issue in a product.
//
// Writing asks for triage on that product at the issue's visibility there,
// which is the same rule a claim comment holds to: saying something on the
// record about work is part of arguing about it. Reading is wider and is
// answered by Notes.
func (s *Store) NoteOn(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64, body string) (*IssueNote, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, errors.New("a note is recorded as written by whoever wrote it")
	}
	if strings.TrimSpace(body) == "" {
		return nil, errors.New("a note has to say something")
	}
	if err := markdown.Check(body); err != nil {
		return nil, err
	}
	told, at, err := s.noteReach(ctx, subject, productID, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	// Refused as a name nobody has used, so that a product somebody holds
	// nothing on and an issue that is not there answer alike.
	if !told {
		return nil, ErrNoSuchNote
	}
	if !subject.Triages(at, productID) && !subject.OnCase(productID, vulnerabilityID) {
		return nil, access.Denied("write a note about an issue here")
	}

	note := &IssueNote{
		VulnerabilityID: vulnerabilityID, ProductID: productID, Body: body,
		WrittenBy: subject.ID, WrittenAt: s.now().Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(note).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record a note: %w", err)
	}
	return note, noting(ctx, s.db, body, note.WrittenAt)
}

// RewordNote changes a note, which only its author may do.
//
// Overwritten rather than revised, and marked as edited. Nobody else may
// change somebody's words — an edit that could be made by another person is
// not a correction, it is a forgery with a timestamp.
//
// **Whether the asker may reach the note is settled before anything about it
// is said back.** The row is read first, because the issue and product it
// hangs off are not knowable otherwise, but no answer turns on what was in it
// until the asker has been let in: refusing on authorship first would tell
// anybody with an account that a note with this identifier exists, one request
// at a time, including on issues nobody has disclosed.
func (s *Store) RewordNote(ctx context.Context, subject access.Subject, noteID int64,
	body string) (*IssueNote, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, ErrNoSuchNote
	}
	if strings.TrimSpace(body) == "" {
		return nil, errors.New("a note has to say something")
	}
	if err := markdown.Check(body); err != nil {
		return nil, err
	}

	note := new(IssueNote)
	edited := s.now().Truncate(time.Microsecond)
	// Everything this decides on is read inside the transaction that writes.
	// A retry re-runs the closure against a database that has moved, so a
	// value fetched before it began describes a world that is gone — and one
	// of those values is whether the asker may be here at all.
	//
	// What it said before is kept in the same transaction for a second
	// reason: written apart, an edit that succeeded beside a history write
	// that did not would leave the record saying a note was changed and
	// nothing saying from what, which is worse than keeping no history
	// because it looks like one.
	db, ok := database.Handle(s.db)
	if !ok {
		return nil, errors.New("this store is already inside a transaction")
	}
	if err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		if err := tx.NewSelect().Model(note).Where("id = ?", noteID).Scan(ctx); err != nil {
			return ErrNoSuchNote
		}
		told, at, err := noteReach(ctx, tx, subject, note.ProductID, note.VulnerabilityID)
		if err != nil {
			return err
		}
		if !told {
			return ErrNoSuchNote
		}
		if !subject.Triages(at, note.ProductID) &&
			!subject.OnCase(note.ProductID, note.VulnerabilityID) {
			return access.Denied("change a note about an issue here")
		}
		if note.WrittenBy != subject.ID {
			return errors.New("only the person who wrote a note may change it")
		}
		// The ordinal is read inside the transaction, so two edits at once
		// cannot be handed the same number: the unique index refuses the
		// second, and the loser retries against a database that has moved.
		var highest int
		if err := tx.NewSelect().Model((*WasNoted)(nil)).
			ColumnExpr("COALESCE(MAX(ordinal), 0)").
			Where("note_id = ?", noteID).Scan(ctx, &highest); err != nil {
			return err
		}
		// And what it says now, read here rather than carried in from the
		// lookup above. A retry that used the text read before the first
		// attempt would record that as the previous version while an edit
		// that landed in between became one nothing kept.
		var was string
		if err := tx.NewSelect().Model((*IssueNote)(nil)).
			Column("body").Where("id = ?", noteID).Scan(ctx, &was); err != nil {
			return err
		}
		if _, err := tx.NewInsert().Model(&WasNoted{
			NoteID: noteID, Ordinal: highest + 1, Body: was, ReplacedAt: edited,
		}).Exec(ctx); err != nil {
			return fmt.Errorf("keep what it said before: %w", err)
		}
		if _, err := tx.NewUpdate().Model((*IssueNote)(nil)).
			Set("body = ?", body).
			Set("edited_at = ?", edited).
			Where("id = ?", noteID).Exec(ctx); err != nil {
			return fmt.Errorf("change a note: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	note.Body, note.EditedAt = body, &edited
	// An edit can add a reference the first version did not have. It can also
	// take one away, and that does not un-attach the file: the revision that
	// referred to it is still on record.
	return note, noting(ctx, s.db, body, edited)
}

// Notes is what has been written about an issue in a product, oldest first.
//
// Read by whoever may read a finding of that issue in that product, at its
// visibility — the rule every other read of the record follows (REQ-43). A
// product the reader holds nothing on answers as an issue that is not there.
func (s *Store) Notes(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) ([]IssueNote, error) {

	told, at, err := s.noteReach(ctx, subject, productID, vulnerabilityID)
	if err != nil {
		return nil, err
	}
	if !told {
		return nil, ErrNoSuchNote
	}
	if !subject.Reads(at, productID) && !subject.OnCase(productID, vulnerabilityID) {
		return nil, ErrNoSuchNote
	}
	var notes []IssueNote
	if err := s.db.NewSelect().Model(&notes).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("product_id = ?", productID).
		Order("id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the notes on this issue: %w", err)
	}
	return notes, nil
}

// EarlierNote is what a note said before, oldest first.
//
// Narrowed by the issue and product it belongs to rather than by the note: who
// may read a note is who may read what it is about, and asking the question
// about the note alone would be a second rule to keep in step.
func (s *Store) EarlierNote(ctx context.Context, subject access.Subject,
	noteID int64) ([]WasNoted, error) {

	note := new(IssueNote)
	if err := s.db.NewSelect().Model(note).Where("id = ?", noteID).Scan(ctx); err != nil {
		return nil, ErrNoSuchNote
	}
	if _, err := s.Notes(ctx, subject, note.ProductID, note.VulnerabilityID); err != nil {
		return nil, err
	}
	var rows []WasNoted
	if err := s.db.NewSelect().Model(&rows).
		Where("note_id = ?", noteID).Order("ordinal").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what it said before: %w", err)
	}
	return rows, nil
}

// NoteVisibility is how disclosed a note about this issue in this product is.
//
// Asked without a subject, because it is a property of the thing rather than
// of who is looking: what it answers is which visibility a reader has to hold,
// and the caller is the one holding the reader.
func (s *Store) NoteVisibility(ctx context.Context, productID,
	vulnerabilityID int64) (access.Visibility, error) {

	return noteVisibility(ctx, s.db, productID, vulnerabilityID)
}

func noteVisibility(ctx context.Context, db bun.IDB, productID,
	vulnerabilityID int64) (access.Visibility, error) {

	hidden, err := db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("f.id").
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("st.product_id = ?", productID).
		Where("f.visibility = ?", access.Private).
		Exists(ctx)
	if err != nil {
		return access.Public, fmt.Errorf("read whether this issue is announced here: %w", err)
	}
	if hidden {
		return access.Private, nil
	}
	return access.Public, nil
}

// noteReach is whether this subject may be told the issue is in this product
// at all, and at what visibility a note about it is held.
//
// **Undisclosed if any place of the issue in this product is**, which is the
// rule the finding screen already applies to what may be said: one undisclosed
// place among fifty makes the whole of it undisclosed for anybody deciding
// what to write. A note is one thread for the issue, so it cannot be public
// for some of its places and private for others — and the safe direction is
// the stricter one.
//
// The telling half comes first, and its refusal is spelled as an unused name,
// so a product somebody holds nothing on and an issue that is not there answer
// alike (REQ-42).
func (s *Store) noteReach(ctx context.Context, subject access.Subject,
	productID, vulnerabilityID int64) (bool, access.Visibility, error) {

	return noteReach(ctx, s.db, subject, productID, vulnerabilityID)
}

// noteReach against a handle the caller chooses, so that the write below can
// ask it from inside its own transaction: a retry re-runs the closure against
// a database that has moved, and an authorization answered outside describes a
// world that is gone.
func noteReach(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, vulnerabilityID int64) (bool, access.Visibility, error) {

	told, err := finding.MayBeToldOfWithin(ctx, db, subject, productID, vulnerabilityID)
	if err != nil || !told {
		return false, access.Public, err
	}
	at, err := noteVisibility(ctx, db, productID, vulnerabilityID)
	return err == nil, at, err
}
