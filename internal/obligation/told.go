// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Told is a record that somebody outside was told about an attack: who, when,
// and what they were told.
//
// The shape of the record of an advisory going out. A fact about a moment,
// kept because the moment is gone by the time anybody asks, and append-only
// for the reason that record is: what was said to a regulator is not unsaid
// by editing a row. A notice recorded in error is answered by recording the
// correction beside it.
type Told struct {
	bun.BaseModel `bun:"table:told_outside,alias:tod"`

	ID int64 `bun:"id,pk,autoincrement"`
	// ExploitedHereID is the record of an attack this notice is about. A
	// cleared record and the one recorded after it are two incidents, so a
	// notice belongs to one of them rather than to the issue.
	ExploitedHereID int64 `bun:"exploited_here_id,notnull"`
	// WindowID is the window this notice answers, where whoever recorded it
	// said so. Their statement: nothing here decides whether a notice met a
	// window, and a notice naming none answers none.
	WindowID *int64 `bun:"window_id"`
	// Recipient is who was told: a regulator, a customer, a response team.
	Recipient string `bun:"recipient,notnull"`
	// ToldAt is when they were told. Supplied, for the reason the moment an
	// attack became known is: the telling happens before the typing.
	ToldAt time.Time `bun:"told_at,notnull"`
	// Said is what they were told.
	Said       string    `bun:"said,notnull"`
	RecordedBy int64     `bun:"recorded_by,notnull"`
	RecordedAt time.Time `bun:"recorded_at,notnull"`
	// Reference is what the recipient called the notice, where they gave it
	// a reference: a case number, a submission identifier.
	Reference *string `bun:"reference"`
	// Malicious is what the notice said about whether the attack was
	// malicious, one of the Malice words, or nil where it said nothing.
	Malicious *string `bun:"suspected_malicious"`
	// Places is the places the notice named, in the order they were given.
	Places []string `bun:"-"`
}

// ToldPlace is one place a notice named.
type ToldPlace struct {
	bun.BaseModel `bun:"table:told_place,alias:tpl"`

	ToldID   int64  `bun:"told_id,pk"`
	Position int    `bun:"position,pk"`
	Place    string `bun:"place,notnull"`
}

// Details is what a notice may say beyond who, when and what. Each is
// optional, and each is the statement of whoever recorded the notice.
type Details struct {
	// Reference is what the recipient called the notice.
	Reference string
	// Places is the places the notice named.
	Places []string
	// Malicious is one of the Malice words, or empty where the notice said
	// nothing about malice.
	Malicious string
}

// What a notice may say about whether an attack was malicious. Unknown is a
// statement of its own: a notice saying malice is not known says something a
// notice silent on it does not.
const (
	MaliciousYes     = "yes"
	MaliciousNo      = "no"
	MaliciousUnknown = "unknown"
)

// Malice is every word a notice may say about malice, in the order a form
// offers them.
var Malice = []string{MaliciousYes, MaliciousNo, MaliciousUnknown}

// PlacesLimit is how many places one notice may name: every country in the
// world, with room to spare, and a bound on what one request writes.
const PlacesLimit = 250

// RecipientLimit is how long a recipient's name may be, in characters: a name
// rather than an address book.
const RecipientLimit = 200

// ErrNoSuchRecord is returned where a record of being exploited is missing or
// is about an issue this subject may not be told of. One error for both,
// because telling them apart turns a record identifier into a directory.
var ErrNoSuchRecord = refusal.New("no record of being exploited is kept there")

// RecordTold records that somebody outside was told about an attack.
//
// Asked of triage on the product the record belongs to, which is what
// recording the attack asks: the notice is part of answering it. Allowed on a
// record since cleared, because a notice given before the clearing is still a
// thing that happened.
func (s *Store) RecordTold(ctx context.Context, subject access.Subject, recordID int64,
	windowID *int64, recipient string, toldAt time.Time, said string,
	details Details) (*Told, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, refusal.New("a notice is recorded against whoever recorded it")
	}
	recipient = strings.TrimSpace(recipient)
	if recipient == "" {
		return nil, refusal.New("say who was told")
	}
	if utf8.RuneCountInString(recipient) > RecipientLimit {
		return nil, refusal.Errorf("who was told is at most %d characters", RecipientLimit)
	}
	if strings.TrimSpace(said) == "" {
		return nil, refusal.New(
			"say what they were told. A notice is read later by somebody answering for it, " +
				"and what was said is the part they cannot find anywhere else")
	}
	if len(said) > triage.GroundsLimit {
		return nil, refusal.Errorf("what they were told is longer than %d bytes", triage.GroundsLimit)
	}
	if err := markdown.Check(said); err != nil {
		return nil, err
	}
	if toldAt.IsZero() {
		return nil, refusal.New("say when they were told")
	}
	reference, malicious, places, err := detailsSaid(details)
	if err != nil {
		return nil, err
	}
	if toldAt.After(s.now()) {
		return nil, refusal.New("say when they were told. A moment still to come is not one anybody was told at")
	}

	told := new(Told)
	err = s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		*told = Told{}
		record := new(triage.ExploitedHere)
		if err := tx.NewSelect().Model(record).Where("eh.id = ?", recordID).
			Scan(ctx); err != nil {
			if database.IsNoRows(err) {
				return ErrNoSuchRecord
			}
			return fmt.Errorf("read the record of being exploited: %w", err)
		}
		if !subject.TriagesIn(record.ProductID) {
			return ErrNoSuchRecord
		}
		// Inside the transaction, because a retry re-runs this against a
		// database that has moved.
		allowed, err := finding.MayBeToldOfWithin(ctx, tx, subject,
			record.ProductID, record.VulnerabilityID)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrNoSuchRecord
		}
		// Not before the attack became known. A notice about something
		// nobody here knew of yet is a mistake in one moment or the other,
		// and the record is the one already kept.
		if toldAt.Before(record.KnownAt) {
			return refusal.Errorf("that is before this became known, at %s. Correct whichever of "+
				"the two is wrong", record.KnownAt.Format(time.RFC3339))
		}
		if windowID != nil {
			window, err := inForce(ctx, tx, *windowID)
			if err != nil {
				return err
			}
			// Only a window that applies to this record's product. One limited
			// to other products is not one this record answers, and its name
			// is not the caller's to learn, so it is refused as one nobody
			// declared.
			if !window.AppliesTo(record.ProductID) {
				return ErrNoSuchWindow
			}
		}
		*told = Told{
			ExploitedHereID: record.ID, WindowID: windowID,
			Recipient: recipient, ToldAt: toldAt.UTC().Truncate(time.Microsecond),
			Said: said, RecordedBy: subject.ID,
			RecordedAt: s.now().Truncate(time.Microsecond),
			Reference:  reference, Malicious: malicious, Places: places,
		}
		if _, err := tx.NewInsert().Model(told).Exec(ctx); err != nil {
			return fmt.Errorf("record that somebody outside was told: %w", err)
		}
		if len(places) == 0 {
			return nil
		}
		rows := make([]ToldPlace, 0, len(places))
		for i, place := range places {
			rows = append(rows, ToldPlace{ToldID: told.ID, Position: i, Place: place})
		}
		if _, err := tx.NewInsert().Model(&rows).Exec(ctx); err != nil {
			return fmt.Errorf("record the places a notice named: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return told, nil
}

// detailsSaid checks what a notice says beyond who, when and what, before any
// of it is stored.
//
// A place named twice, in any capitals, is kept once, as it was first typed.
// A blank place is refused rather than dropped: it is a slip in what was
// typed, and the rest of the list may be wrong with it.
func detailsSaid(details Details) (reference, malicious *string, places []string, err error) {
	if typed := strings.TrimSpace(details.Reference); typed != "" {
		if utf8.RuneCountInString(typed) > database.NameWidth {
			return nil, nil, nil, refusal.Errorf("a reference is at most %d characters", database.NameWidth)
		}
		reference = &typed
	}
	if details.Malicious != "" {
		if !slices.Contains(Malice, details.Malicious) {
			return nil, nil, nil, refusal.Errorf("say whether it was malicious as one of %s, or leave it out",
				strings.Join(Malice, ", "))
		}
		said := details.Malicious
		malicious = &said
	}
	if len(details.Places) > PlacesLimit {
		return nil, nil, nil, refusal.Errorf("a notice names at most %d places", PlacesLimit)
	}
	seen := map[string]bool{}
	for _, typed := range details.Places {
		place := strings.TrimSpace(typed)
		if place == "" {
			return nil, nil, nil, refusal.New("a place named is not blank")
		}
		if utf8.RuneCountInString(place) > database.NameWidth {
			return nil, nil, nil, refusal.Errorf("a place's name is at most %d characters", database.NameWidth)
		}
		if seen[strings.ToLower(place)] {
			continue
		}
		seen[strings.ToLower(place)] = true
		places = append(places, place)
	}
	return reference, malicious, places, nil
}

// ToldAbout is every notice recorded about these records that this subject
// may be told of, earliest told first.
//
// Narrowed by the record each notice is about, with the question that
// authorizes one issue in one product: a notice names an attack, and an
// attack on an undisclosed issue is undisclosed with it.
func (s *Store) ToldAbout(ctx context.Context, subject access.Subject,
	recordIDs []int64) (map[int64][]Told, error) {

	out := map[int64][]Told{}
	if len(recordIDs) == 0 {
		return out, nil
	}
	var records []triage.ExploitedHere
	if err := s.db.NewSelect().Model(&records).
		Where("eh.id IN (?)", bun.List(recordIDs)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the records of being exploited: %w", err)
	}
	allowed := make([]int64, 0, len(records))
	for _, record := range records {
		ok, err := finding.MayBeToldOfWithin(ctx, s.db, subject,
			record.ProductID, record.VulnerabilityID)
		if err != nil {
			return nil, err
		}
		if ok {
			allowed = append(allowed, record.ID)
		}
	}
	if len(allowed) == 0 {
		return out, nil
	}
	var rows []Told
	err := s.db.NewSelect().Model(&rows).
		Where("tod.exploited_here_id IN (?)", bun.List(allowed)).
		Order("tod.told_at ASC", "tod.id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who outside was told: %w", err)
	}
	if err := withPlaces(ctx, s.db, rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		out[row.ExploitedHereID] = append(out[row.ExploitedHereID], row)
	}
	return out, nil
}

// withPlaces fills in the places each notice named, which the notice row
// itself does not carry.
func withPlaces(ctx context.Context, db bun.IDB, told []Told) error {
	if len(told) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(told))
	at := make(map[int64]int, len(told))
	for i, one := range told {
		ids = append(ids, one.ID)
		at[one.ID] = i
	}
	var places []ToldPlace
	if err := db.NewSelect().Model(&places).
		Where("tpl.told_id IN (?)", bun.List(ids)).
		Order("tpl.told_id ASC", "tpl.position ASC").
		Scan(ctx); err != nil {
		return fmt.Errorf("read the places notices named: %w", err)
	}
	for _, place := range places {
		one := &told[at[place.ToldID]]
		one.Places = append(one.Places, place.Place)
	}
	return nil
}

// WindowsNamed is the name of every window these notices point at that this
// subject may read, retired ones included: a notice keeps naming the window it
// answered.
//
// Read as the list of windows is. A window limited since to products the
// subject may not know exist is left out, and its notices name no window,
// because its current name is the administrator's statement about those
// products.
func (s *Store) WindowsNamed(ctx context.Context, subject access.Subject,
	told map[int64][]Told) (map[int64]string, error) {
	wanted := map[int64]bool{}
	for _, each := range told {
		for _, one := range each {
			if one.WindowID != nil {
				wanted[*one.WindowID] = true
			}
		}
	}
	named := map[int64]string{}
	if len(wanted) == 0 {
		return named, nil
	}
	ids := make([]int64, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	var windows []Window
	if err := s.db.NewSelect().Model(&windows).
		Where("ow.id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which windows were answered: %w", err)
	}
	windows, err := withLimits(ctx, s.db, windows)
	if err != nil {
		return nil, err
	}
	for _, window := range windows {
		if shown, ok := window.As(subject); ok {
			named[shown.ID] = shown.Name
		}
	}
	return named, nil
}
