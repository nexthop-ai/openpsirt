// Package obligation holds what a deployment answers to after its product is
// attacked: the windows it says it is under, the record that somebody outside
// was told, and the shelf that watches both.
//
// Recorded, never computed. Nothing here decides whether a window applies to
// an incident, when a regulator's clock started, or whether a notice met
// anything. What it holds are the facts those questions are answered from:
// when an attack became known, which windows this deployment counts, and who
// was told what and when.
package obligation

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Window is a period a deployment says it answers within, counted from the
// moment an attack became known.
//
// None ships. A window is somebody's reading of rules this software does not
// know, and a default would be that reading made for every deployment by
// nobody who holds it.
type Window struct {
	bun.BaseModel `bun:"table:obligation_window,alias:ow"`

	ID int64 `bun:"id,pk,autoincrement"`
	// Name is what the window is called here, as it was typed.
	Name string `bun:"name,notnull"`
	// Hours is how long the window runs. Hours rather than days, because the
	// shortest windows in force anywhere are a day.
	Hours      int       `bun:"length_hours,notnull"`
	DeclaredBy int64     `bun:"declared_by,notnull"`
	DeclaredAt time.Time `bun:"declared_at,notnull"`
	// RetiredAt is when this stopped being counted. Retired rather than
	// deleted, because a notice recorded against it keeps naming it.
	RetiredAt *time.Time `bun:"retired_at"`
	// LiveName is the name folded for comparison while the window is in
	// force, and null once it is retired. Unique, so two windows in force
	// cannot share a name and a retired one does not hold its name back.
	LiveName *string `bun:"live_name"`
}

// Length is how long the window runs.
func (w Window) Length() time.Duration { return time.Duration(w.Hours) * time.Hour }

// EndsAt is when the window counted from this moment closes.
func (w Window) EndsAt(knownAt time.Time) time.Time { return knownAt.Add(w.Length()) }

// LongestHours bounds a window at a year. A window longer than that is not
// one anybody is watched against, and the bound keeps the arithmetic of an
// end well inside what every engine stores.
const LongestHours = 24 * 366

// ErrNoSuchWindow is returned where a window is missing or retired.
var ErrNoSuchWindow = errors.New("no window in force goes by that")

// ErrWindowNamed is returned where a window in force already has the name.
var ErrWindowNamed = errors.New("a window in force already has that name")

// Store reads and writes obligations.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// folded is a window's name as it is compared: without regard to capitals or
// the space around it, the way every name people type is matched here.
func folded(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// windowSaid checks a name and a length before either is stored.
func windowSaid(name string, hours int) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("a window needs a name")
	}
	if utf8.RuneCountInString(name) > database.NameWidth {
		return "", fmt.Errorf("a window's name is at most %d characters", database.NameWidth)
	}
	// Zero reads as unset everywhere, so it is refused rather than stored as
	// a window that closes the moment it opens.
	if hours <= 0 {
		return "", errors.New("a window runs for at least an hour")
	}
	if hours > LongestHours {
		return "", fmt.Errorf("a window runs for at most %d hours", LongestHours)
	}
	return name, nil
}

// Windows is every window in force, shortest first: the order they close in
// for any one incident.
func (s *Store) Windows(ctx context.Context) ([]Window, error) {
	var windows []Window
	err := s.db.NewSelect().Model(&windows).
		Where("ow.retired_at IS NULL").
		Order("ow.length_hours ASC", "ow.id ASC").
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the windows in force: %w", err)
	}
	return windows, nil
}

// DeclareWindow adds a window this deployment counts.
//
// An administrator's act, and one the trail records: a window decides what
// every incident is watched against from now on, which is the layer a setting
// sits in.
func (s *Store) DeclareWindow(ctx context.Context, subject access.Subject, name string,
	hours int) (*Window, error) {

	if !subject.Admin || subject.Kind != access.Person {
		return nil, access.Denied("declare a window")
	}
	name, err := windowSaid(name, hours)
	if err != nil {
		return nil, err
	}
	window := new(Window)
	err = s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		live := folded(name)
		*window = Window{
			Name: name, Hours: hours, DeclaredBy: subject.ID,
			DeclaredAt: s.now().Truncate(time.Microsecond), LiveName: &live,
		}
		if _, err := tx.NewInsert().Model(window).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				return ErrWindowNamed
			}
			return fmt.Errorf("declare a window: %w", err)
		}
		return noteWindow(ctx, tx, subject, name, nil, said(hours))
	})
	if err != nil {
		return nil, err
	}
	return window, nil
}

// ChangeWindow renames a window in force or changes how long it runs.
//
// Every incident's end moves with it, because an end is worked out from the
// window as it stands rather than stored. A notice already recorded against
// the window keeps pointing at it.
func (s *Store) ChangeWindow(ctx context.Context, subject access.Subject, id int64,
	name string, hours int) (*Window, error) {

	if !subject.Admin || subject.Kind != access.Person {
		return nil, access.Denied("change a window")
	}
	name, err := windowSaid(name, hours)
	if err != nil {
		return nil, err
	}
	window := new(Window)
	err = s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		*window = Window{}
		if err := tx.NewSelect().Model(window).
			Where("ow.id = ?", id).Where("ow.retired_at IS NULL").
			Scan(ctx); err != nil {
			if database.IsNoRows(err) {
				return ErrNoSuchWindow
			}
			return fmt.Errorf("read the window: %w", err)
		}
		was := window.Name + " " + strconv.Itoa(window.Hours) + "h"
		live := folded(name)
		if _, err := tx.NewUpdate().Model((*Window)(nil)).
			Set("name = ?", name).
			Set("length_hours = ?", hours).
			Set("live_name = ?", live).
			Where("id = ?", id).
			Where("retired_at IS NULL").
			Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				return ErrWindowNamed
			}
			return fmt.Errorf("change a window: %w", err)
		}
		window.Name, window.Hours, window.LiveName = name, hours, &live
		became := name + " " + strconv.Itoa(hours) + "h"
		return noteWindow(ctx, tx, subject, name, &was, &became)
	})
	if err != nil {
		return nil, err
	}
	return window, nil
}

// RetireWindow stops counting a window.
//
// Retired rather than deleted: a notice recorded against it keeps naming it,
// and the name is released so it may be declared again.
func (s *Store) RetireWindow(ctx context.Context, subject access.Subject, id int64) error {
	if !subject.Admin || subject.Kind != access.Person {
		return access.Denied("retire a window")
	}
	return s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		window := new(Window)
		if err := tx.NewSelect().Model(window).
			Where("ow.id = ?", id).Where("ow.retired_at IS NULL").
			Scan(ctx); err != nil {
			if database.IsNoRows(err) {
				return ErrNoSuchWindow
			}
			return fmt.Errorf("read the window: %w", err)
		}
		res, err := tx.NewUpdate().Model((*Window)(nil)).
			Set("retired_at = ?", s.now().Truncate(time.Microsecond)).
			Set("live_name = ?", nil).
			Where("id = ?", id).
			// Still in force when this lands, so two retirements at once
			// record one act rather than two.
			Where("retired_at IS NULL").
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("retire a window: %w", err)
		}
		retired, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("retire a window: %w", err)
		}
		if retired == 0 {
			return ErrNoSuchWindow
		}
		return noteWindow(ctx, tx, subject, window.Name, said(window.Hours), nil)
	})
}

// writing runs do inside one transaction, retried as a whole.
func (s *Store) writing(ctx context.Context,
	do func(ctx context.Context, tx bun.IDB) error) error {

	return database.Within(ctx, s.db, do)
}

// said is a window's length as the trail records it.
func said(hours int) *string {
	return trail.Said(strconv.Itoa(hours)+"h", true)
}

// noteWindow writes a change to a window into the administrative trail, in
// the transaction that makes it.
func noteWindow(ctx context.Context, tx bun.IDB, subject access.Subject, name string,
	was, became *string) error {

	return trail.NewStore(tx).Record(ctx, subject, trail.Setting,
		"Obligation window "+name, was, became)
}
