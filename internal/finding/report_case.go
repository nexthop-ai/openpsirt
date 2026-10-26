// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// A report as a case: what it said before each edit, the messages exchanged
// with whoever sent it, and the notes people here write on it.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ReportRevision is what a report said before one edit replaced it.
type ReportRevision struct {
	bun.BaseModel `bun:"table:flaw_report_revision,alias:frr"`

	ID           int64 `bun:"id,pk,autoincrement"`
	FlawReportID int64 `bun:"flaw_report_id,notnull"`
	// Ordinal is which version this was, counting from one. Version one is
	// the report as it was first recorded.
	Ordinal    int        `bun:"ordinal,notnull"`
	Title      string     `bun:"title"`
	Summary    string     `bun:"summary"`
	ReportedBy string     `bun:"reported_by"`
	Contact    string     `bun:"contact"`
	Credit     string     `bun:"credit"`
	ReceivedOn *time.Time `bun:"received_on"`
	ReplacedBy int64      `bun:"replaced_by,notnull"`
	ReplacedAt time.Time  `bun:"replaced_at,notnull"`
}

// Rewritten is what a report says after an edit. Every field is the whole new
// value; one left empty is cleared, apart from the claim, which is required.
type Rewritten struct {
	Title      string
	Summary    string
	ReportedBy string
	Contact    string
	Credit     string
	// Received is the day it arrived, as a date. Empty clears it, and a date
	// that cannot be read is refused.
	Received string
}

// The refusals an edit and a logged message have of their own.
var (
	ErrUnreadableDay = refusal.New("give the day as YYYY-MM-DD")
	ErrTitleOneLine  = refusal.New("a title is one line")
	ErrMessageEmpty  = refusal.New("say what the message said")
	ErrNoDirection   = refusal.New("say whether the message was sent or received")
	ErrDatedAhead    = refusal.New("that day has not happened yet")
	ErrFoundHere     = refusal.New(
		"a flaw found here has no reporter, so there is no correspondence to record")
	ErrNoSuchReportNote = refusal.New("no note on that report goes by that number")
	ErrNoteNotYours     = refusal.New("only the person who wrote a note may change it")
	ErrNoteSaysNothing  = refusal.New("a note has to say something")
)

// titled is a title as it is stored: trimmed, and refused across lines.
func titled(typed string) (string, error) {
	title := strings.TrimSpace(typed)
	if strings.ContainsAny(title, "\r\n") {
		return "", ErrTitleOneLine
	}
	return title, nil
}

// claimed is a claim as it is stored: trimmed, required, and through the
// submission policy a justification goes through.
func claimed(typed string) (string, error) {
	summary := strings.TrimSpace(typed)
	if summary == "" {
		return "", ErrNothingClaimed
	}
	if err := markdown.Check(summary); err != nil {
		return "", err
	}
	return summary, nil
}

// reportIn reads one report by its reference, through the handle given, with
// no authorization of its own: every caller has authorized the product first.
func reportIn(ctx context.Context, db bun.IDB, productID int64, reference string) (*FlawReport, error) {
	row := new(FlawReport)
	err := db.NewSelect().Model(row).
		Where(`"fr"."reference" = ?`, foldReference(reference)).
		Where(`"fr"."product_id" = ?`, productID).
		Scan(ctx)
	switch {
	case database.IsNoRows(err):
		return nil, ErrNoSuchReport
	case err != nil:
		return nil, fmt.Errorf("read a report: %w", err)
	}
	return row, nil
}

// Revise changes what a report says: its title, its claim, and who sent it.
//
// Only while it is open. A report judged, or under a ruling waiting for a
// second person, is what was judged, and an edit after that would change the
// text a decision was made on. What it said before is kept as a revision in
// the same transaction, so the original is always readable.
func (s *Store) Revise(ctx context.Context, subject access.Subject, productID int64,
	reference string, in Rewritten) (*FlawReport, error) {

	if err := mayWorkReference(subject, productID); err != nil {
		return nil, err
	}
	summary, err := claimed(in.Summary)
	if err != nil {
		return nil, err
	}
	title, err := titled(in.Title)
	if err != nil {
		return nil, err
	}
	var received *time.Time
	if day := strings.TrimSpace(in.Received); day != "" {
		parsed, err := time.Parse(time.DateOnly, day)
		if err != nil {
			return nil, ErrUnreadableDay
		}
		received = &parsed
	}
	next := FlawReport{
		Title: title, Summary: summary,
		ReportedBy: strings.TrimSpace(in.ReportedBy),
		Contact:    strings.TrimSpace(in.Contact),
		Credit:     strings.TrimSpace(in.Credit),
		ReceivedOn: received,
	}

	var row *FlawReport
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		if row, err = reportIn(ctx, tx, productID, reference); err != nil {
			return err
		}
		if !row.Editable() {
			return ErrAlreadyJudged
		}
		if sameText(*row, next) {
			return nil
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		var highest int
		if err := tx.NewSelect().Model((*ReportRevision)(nil)).
			ColumnExpr(`COALESCE(MAX("ordinal"), 0)`).
			Where(`"flaw_report_id" = ?`, row.ID).Scan(ctx, &highest); err != nil {
			return fmt.Errorf("read how often it was edited: %w", err)
		}
		if _, err := tx.NewInsert().Model(&ReportRevision{
			FlawReportID: row.ID, Ordinal: highest + 1,
			Title: row.Title, Summary: row.Summary,
			ReportedBy: row.ReportedBy, Contact: row.Contact, Credit: row.Credit,
			ReceivedOn: row.ReceivedOn, ReplacedBy: subject.ID, ReplacedAt: now,
		}).Exec(ctx); err != nil {
			return fmt.Errorf("keep what it said before: %w", err)
		}
		res, err := tx.NewUpdate().Model((*FlawReport)(nil)).
			Set(`"title" = ?`, next.Title).
			Set(`"summary" = ?`, next.Summary).
			Set(`"reported_by" = ?`, next.ReportedBy).
			Set(`"contact" = ?`, next.Contact).
			Set(`"credit" = ?`, next.Credit).
			Set(`"received_on" = ?`, next.ReceivedOn).
			Where(`"id" = ?`, row.ID).
			Where(`"vulnerability_id" IS NULL`).
			Where(`"ruling_id" IS NULL`).
			Where(`"evaluated_at" IS NULL`).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("change what it says: %w", err)
		}
		changed, err := database.Affected(res)
		if err != nil {
			return err
		}
		if changed == 0 {
			return ErrAlreadyJudged
		}
		row.Title, row.Summary = next.Title, next.Summary
		row.ReportedBy, row.Contact, row.Credit = next.ReportedBy, next.Contact, next.Credit
		row.ReceivedOn = next.ReceivedOn
		return nil
	})
	if err != nil {
		return nil, err
	}
	return row, nil
}

// sameText reports whether an edit changes nothing a revision would keep.
func sameText(was, next FlawReport) bool {
	sameDay := (was.ReceivedOn == nil) == (next.ReceivedOn == nil) &&
		(was.ReceivedOn == nil || was.ReceivedOn.Format(time.DateOnly) == next.ReceivedOn.Format(time.DateOnly))
	return sameDay && was.Title == next.Title && was.Summary == next.Summary &&
		was.ReportedBy == next.ReportedBy && was.Contact == next.Contact && was.Credit == next.Credit
}

// Revisions is what a report said before each edit, oldest first. The first is
// the report as it was recorded; none is a report never edited.
func (s *Store) Revisions(ctx context.Context, subject access.Subject, productID int64,
	reference string) ([]ReportRevision, error) {

	row, err := s.ReportBy(ctx, subject, productID, reference)
	if err != nil {
		return nil, err
	}
	var rows []ReportRevision
	if err := s.db.NewSelect().Model(&rows).
		Where(`"frr"."flaw_report_id" = ?`, row.ID).
		Order("frr.ordinal").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what it said before: %w", err)
	}
	return rows, nil
}

// RevisionCounts is how often each of these reports was edited, in one read.
func RevisionCounts(ctx context.Context, db bun.IDB, reportIDs []int64) (map[int64]int, error) {
	out := map[int64]int{}
	if len(reportIDs) == 0 {
		return out, nil
	}
	var rows []struct {
		ReportID int64 `bun:"report_id"`
		Edits    int   `bun:"edits"`
	}
	if err := db.NewSelect().Model((*ReportRevision)(nil)).
		ColumnExpr(`"frr"."flaw_report_id" AS "report_id"`).
		ColumnExpr(`COUNT(*) AS "edits"`).
		Where(`"frr"."flaw_report_id" IN (?)`, bun.List(reportIDs)).
		GroupExpr(`"frr"."flaw_report_id"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read how often reports were edited: %w", err)
	}
	for _, row := range rows {
		out[row.ReportID] = row.Edits
	}
	return out, nil
}

// Direction is which way a message between this deployment and a reporter
// went.
type Direction string

// The two directions. The first message sent is the acknowledgement.
const (
	Sent     Direction = "sent"
	Received Direction = "received"
)

// Directions is every direction a message goes.
func Directions() []Direction { return []Direction{Sent, Received} }

// ReportMessage is one message between this deployment and a reporter, as
// somebody here recorded it. Nothing is sent from here: the row records a
// message sent or received elsewhere.
type ReportMessage struct {
	bun.BaseModel `bun:"table:report_message,alias:rm"`

	ID           int64     `bun:"id,pk,autoincrement"`
	FlawReportID int64     `bun:"flaw_report_id,notnull"`
	Direction    Direction `bun:"direction,notnull"`
	// Dated is the day it was sent or received.
	Dated time.Time `bun:"dated,notnull"`
	// Body is the message, pasted or summarized, as markdown. Empty only on
	// a message an upgrade carried over from an acknowledgement, which holds
	// no text.
	Body     string    `bun:"body"`
	LoggedBy int64     `bun:"logged_by,notnull"`
	LoggedAt time.Time `bun:"logged_at,notnull"`
}

// Logged is a message somebody records.
type Logged struct {
	Direction Direction
	// Dated is the day, as a date. Empty is today.
	Dated string
	Body  string
}

// LogMessage records a message sent to or received from a report's reporter,
// and answers the report it was logged on.
//
// Open or judged alike: correspondence goes on after a claim is judged, and
// the reporter is owed the outcome. Refused on a flaw found here, which has
// nobody outside to write to. A day more than one ahead of today is refused,
// because a message cannot have been sent in the future and a day either side
// of midnight is the reach of a time zone.
func (s *Store) LogMessage(ctx context.Context, subject access.Subject, productID int64,
	reference string, in Logged) (*ReportMessage, *FlawReport, error) {

	if err := mayWorkReference(subject, productID); err != nil {
		return nil, nil, err
	}
	if in.Direction != Sent && in.Direction != Received {
		return nil, nil, ErrNoDirection
	}
	body := strings.TrimSpace(in.Body)
	if body == "" {
		return nil, nil, ErrMessageEmpty
	}
	if err := markdown.Check(body); err != nil {
		return nil, nil, err
	}
	today := s.now().UTC()
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	dated := today
	if typed := strings.TrimSpace(in.Dated); typed != "" {
		parsed, err := time.Parse(time.DateOnly, typed)
		if err != nil {
			return nil, nil, ErrUnreadableDay
		}
		if parsed.After(today.AddDate(0, 0, 1)) {
			return nil, nil, ErrDatedAhead
		}
		dated = parsed
	}

	var row *FlawReport
	var message *ReportMessage
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		if row, err = reportIn(ctx, tx, productID, reference); err != nil {
			return err
		}
		if row.FoundHere {
			return ErrFoundHere
		}
		message = &ReportMessage{
			FlawReportID: row.ID, Direction: in.Direction, Dated: dated, Body: body,
			LoggedBy: subject.ID, LoggedAt: s.now().UTC().Truncate(time.Microsecond),
		}
		if _, err := tx.NewInsert().Model(message).Exec(ctx); err != nil {
			return fmt.Errorf("record a message: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return message, row, nil
}

// Messages is a report's correspondence, oldest first by the day each message
// carries and then by when it was recorded.
func (s *Store) Messages(ctx context.Context, subject access.Subject, productID int64,
	reference string) ([]ReportMessage, error) {

	row, err := s.ReportBy(ctx, subject, productID, reference)
	if err != nil {
		return nil, err
	}
	return messagesOf(ctx, s.db, row.ID)
}

// messagesOf is one report's correspondence in order, unauthorized.
func messagesOf(ctx context.Context, db bun.IDB, reportID int64) ([]ReportMessage, error) {
	var rows []ReportMessage
	if err := db.NewSelect().Model(&rows).
		Where(`"rm"."flaw_report_id" = ?`, reportID).
		Order("rm.dated", "rm.id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the correspondence: %w", err)
	}
	return rows, nil
}

// Acknowledgements is the first message sent on each of these reports, which
// is its acknowledgement. A report nothing was sent on is absent.
func Acknowledgements(ctx context.Context, db bun.IDB, reportIDs []int64) (map[int64]ReportMessage, error) {
	out := map[int64]ReportMessage{}
	if len(reportIDs) == 0 {
		return out, nil
	}
	var rows []ReportMessage
	if err := db.NewSelect().Model(&rows).
		Where(`"rm"."flaw_report_id" IN (?)`, bun.List(reportIDs)).
		Where(`"rm"."direction" = ?`, Sent).
		Order("rm.flaw_report_id", "rm.dated", "rm.id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read when reporters were answered: %w", err)
	}
	for _, row := range rows {
		if _, seen := out[row.FlawReportID]; !seen {
			out[row.FlawReportID] = row
		}
	}
	return out, nil
}

// ReportNote is something written on a report by somebody here. It records no
// judgment and is never sent to the reporter.
type ReportNote struct {
	bun.BaseModel `bun:"table:report_note,alias:rn"`

	ID           int64      `bun:"id,pk,autoincrement"`
	FlawReportID int64      `bun:"flaw_report_id,notnull"`
	Body         string     `bun:"body,notnull"`
	WrittenBy    int64      `bun:"written_by,notnull"`
	WrittenAt    time.Time  `bun:"written_at,notnull"`
	EditedAt     *time.Time `bun:"edited_at"`
}

// WasReportNoted is what a note on a report said before it was changed.
type WasReportNoted struct {
	bun.BaseModel `bun:"table:report_note_revision,alias:rnr"`

	ID         int64     `bun:"id,pk,autoincrement"`
	NoteID     int64     `bun:"note_id,notnull"`
	Ordinal    int       `bun:"ordinal,notnull"`
	Body       string    `bun:"body,notnull"`
	ReplacedAt time.Time `bun:"replaced_at,notnull"`
}

// noteText is a note as it is stored.
func noteText(typed string) (string, error) {
	if strings.TrimSpace(typed) == "" {
		return "", ErrNoteSaysNothing
	}
	if err := markdown.Check(typed); err != nil {
		return "", err
	}
	return typed, nil
}

// NoteOnReport writes a note on a report, open or judged, and answers the
// report it was written on.
func (s *Store) NoteOnReport(ctx context.Context, subject access.Subject, productID int64,
	reference, body string) (*ReportNote, *FlawReport, error) {

	if err := mayWorkReference(subject, productID); err != nil {
		return nil, nil, err
	}
	text, err := noteText(body)
	if err != nil {
		return nil, nil, err
	}
	var row *FlawReport
	var note *ReportNote
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		if row, err = reportIn(ctx, tx, productID, reference); err != nil {
			return err
		}
		note = &ReportNote{FlawReportID: row.ID, Body: text, WrittenBy: subject.ID,
			WrittenAt: s.now().UTC().Truncate(time.Microsecond)}
		if _, err := tx.NewInsert().Model(note).Exec(ctx); err != nil {
			return fmt.Errorf("record a note: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return note, row, nil
}

// RewordReportNote changes a note on a report, which only its author may do.
// What it said before is kept in the same transaction.
func (s *Store) RewordReportNote(ctx context.Context, subject access.Subject, productID int64,
	reference string, noteID int64, body string) (*ReportNote, *FlawReport, error) {

	if err := mayWorkReference(subject, productID); err != nil {
		return nil, nil, err
	}
	text, err := noteText(body)
	if err != nil {
		return nil, nil, err
	}
	var row *FlawReport
	note := new(ReportNote)
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		if row, err = reportIn(ctx, tx, productID, reference); err != nil {
			return err
		}
		if err := tx.NewSelect().Model(note).
			Where(`"rn"."id" = ?`, noteID).
			Where(`"rn"."flaw_report_id" = ?`, row.ID).Scan(ctx); err != nil {
			return database.FromRead(err, ErrNoSuchReportNote, "read a note on a report")
		}
		if note.WrittenBy != subject.ID {
			return ErrNoteNotYours
		}
		edited := s.now().UTC().Truncate(time.Microsecond)
		var highest int
		if err := tx.NewSelect().Model((*WasReportNoted)(nil)).
			ColumnExpr(`COALESCE(MAX("ordinal"), 0)`).
			Where(`"note_id" = ?`, noteID).Scan(ctx, &highest); err != nil {
			return fmt.Errorf("read how often it was changed: %w", err)
		}
		if _, err := tx.NewInsert().Model(&WasReportNoted{
			NoteID: noteID, Ordinal: highest + 1, Body: note.Body, ReplacedAt: edited,
		}).Exec(ctx); err != nil {
			return fmt.Errorf("keep what it said before: %w", err)
		}
		if _, err := tx.NewUpdate().Model((*ReportNote)(nil)).
			Set(`"body" = ?`, text).
			Set(`"edited_at" = ?`, edited).
			Where(`"id" = ?`, noteID).Exec(ctx); err != nil {
			return fmt.Errorf("change a note: %w", err)
		}
		note.Body, note.EditedAt = text, &edited
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return note, row, nil
}

// ReportNotes is what has been written on a report, oldest first.
func (s *Store) ReportNotes(ctx context.Context, subject access.Subject, productID int64,
	reference string) ([]ReportNote, error) {

	row, err := s.ReportBy(ctx, subject, productID, reference)
	if err != nil {
		return nil, err
	}
	return notesOf(ctx, s.db, row.ID)
}

// notesOf is one report's notes in order, unauthorized.
func notesOf(ctx context.Context, db bun.IDB, reportID int64) ([]ReportNote, error) {
	var rows []ReportNote
	if err := db.NewSelect().Model(&rows).
		Where(`"rn"."flaw_report_id" = ?`, reportID).
		Order("rn.id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the notes on a report: %w", err)
	}
	return rows, nil
}

// EarlierReportNote is what a note on a report said before, oldest first.
func (s *Store) EarlierReportNote(ctx context.Context, subject access.Subject, productID int64,
	reference string, noteID int64) ([]WasReportNoted, error) {

	notes, err := s.ReportNotes(ctx, subject, productID, reference)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(notes, func(n ReportNote) bool { return n.ID == noteID }) {
		return nil, ErrNoSuchReportNote
	}
	var rows []WasReportNoted
	if err := s.db.NewSelect().Model(&rows).
		Where(`"rnr"."note_id" = ?`, noteID).
		Order("rnr.ordinal").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what it said before: %w", err)
	}
	return rows, nil
}
