// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
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
}

// RecipientLimit is how long a recipient's name may be, in characters: a name
// rather than an address book.
const RecipientLimit = 200

// ErrNoSuchRecord is returned where a record of being exploited is missing or
// is about an issue this subject may not be told of. One error for both,
// because telling them apart turns a record identifier into a directory.
var ErrNoSuchRecord = errors.New("no record of being exploited is kept there")

// RecordTold records that somebody outside was told about an attack.
//
// Asked of triage on the product the record belongs to, which is what
// recording the attack asks: the notice is part of answering it. Allowed on a
// record since cleared, because a notice given before the clearing is still a
// thing that happened.
func (s *Store) RecordTold(ctx context.Context, subject access.Subject, recordID int64,
	windowID *int64, recipient string, toldAt time.Time, said string) (*Told, error) {

	if subject.Kind != access.Person || subject.ID == 0 {
		return nil, errors.New("a notice is recorded against whoever recorded it")
	}
	recipient = strings.TrimSpace(recipient)
	if recipient == "" {
		return nil, errors.New("say who was told")
	}
	if utf8.RuneCountInString(recipient) > RecipientLimit {
		return nil, fmt.Errorf("who was told is at most %d characters", RecipientLimit)
	}
	if strings.TrimSpace(said) == "" {
		return nil, errors.New(
			"say what they were told. A notice is read later by somebody answering for it, " +
				"and what was said is the part they cannot find anywhere else")
	}
	if len(said) > triage.GroundsLimit {
		return nil, fmt.Errorf("what they were told is longer than %d bytes", triage.GroundsLimit)
	}
	if err := markdown.Check(said); err != nil {
		return nil, err
	}
	if toldAt.IsZero() {
		return nil, errors.New("say when they were told")
	}
	if toldAt.After(s.now()) {
		return nil, errors.New("say when they were told. A moment still to come is not one anybody was told at")
	}

	told := new(Told)
	err := s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		*told = Told{}
		record := new(triage.ExploitedHere)
		if err := tx.NewSelect().Model(record).Where("eh.id = ?", recordID).
			Scan(ctx); err != nil {
			if database.IsNoRows(err) {
				return ErrNoSuchRecord
			}
			return fmt.Errorf("read the record of being exploited: %w", err)
		}
		if !subject.Triages(access.Public, record.ProductID) {
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
			return fmt.Errorf("that is before this became known, at %s. Correct whichever of "+
				"the two is wrong", record.KnownAt.Format(time.RFC3339))
		}
		if windowID != nil {
			in := new(Window)
			if err := tx.NewSelect().Model(in).
				Where("ow.id = ?", *windowID).Where("ow.retired_at IS NULL").
				Scan(ctx); err != nil {
				if database.IsNoRows(err) {
					return ErrNoSuchWindow
				}
				return fmt.Errorf("read the window: %w", err)
			}
		}
		*told = Told{
			ExploitedHereID: record.ID, WindowID: windowID,
			Recipient: recipient, ToldAt: toldAt.UTC().Truncate(time.Microsecond),
			Said: said, RecordedBy: subject.ID,
			RecordedAt: s.now().Truncate(time.Microsecond),
		}
		if _, err := tx.NewInsert().Model(told).Exec(ctx); err != nil {
			return fmt.Errorf("record that somebody outside was told: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return told, nil
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
	for _, row := range rows {
		out[row.ExploitedHereID] = append(out[row.ExploitedHereID], row)
	}
	return out, nil
}

// WindowsNamed is the name of every window these notices point at, retired
// ones included: a notice keeps naming the window it answered.
func (s *Store) WindowsNamed(ctx context.Context, told map[int64][]Told) (map[int64]string, error) {
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
	for _, window := range windows {
		named[window.ID] = window.Name
	}
	return named, nil
}
