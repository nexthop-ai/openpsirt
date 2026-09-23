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
	Hours int `bun:"length_hours,notnull"`
	// LeadHours is how long before the end a second notice is raised, or nil
	// where the window names none. Each window says its own, because a day's
	// window and a fortnight's want warnings of different sizes.
	LeadHours  *int      `bun:"lead_hours"`
	DeclaredBy int64     `bun:"declared_by,notnull"`
	DeclaredAt time.Time `bun:"declared_at,notnull"`
	// RetiredAt is when this stopped being counted. Retired rather than
	// deleted, because a notice recorded against it keeps naming it.
	RetiredAt *time.Time `bun:"retired_at"`
	// LiveName is the name folded for comparison while the window is in
	// force, and null once it is retired. Unique, so two windows in force
	// cannot share a name and a retired one does not hold its name back.
	LiveName *string `bun:"live_name"`

	// Products is the products the window is limited to, by identifier and
	// by the name an address takes. Empty is every product.
	Products     []int64  `bun:"-"`
	ProductNames []string `bun:"-"`
}

// WindowProduct limits a window to one product.
type WindowProduct struct {
	bun.BaseModel `bun:"table:obligation_window_product,alias:owp"`

	WindowID  int64 `bun:"window_id,pk"`
	ProductID int64 `bun:"product_id,pk"`
}

// WindowSaid is what an administrator states about a window.
type WindowSaid struct {
	Name  string
	Hours int
	// LeadHours is how long before the end the second notice comes, or nil
	// for none.
	LeadHours *int
	// Products names the products the window applies to. Empty is every
	// product.
	Products []string
}

// AppliesTo is whether the window counts for an attack on this product.
func (w Window) AppliesTo(productID int64) bool {
	if len(w.Products) == 0 {
		return true
	}
	for _, id := range w.Products {
		if id == productID {
			return true
		}
	}
	return false
}

// NearAt is when the second notice for an incident known at this moment is
// raised, where the window names a lead time.
func (w Window) NearAt(knownAt time.Time) (time.Time, bool) {
	if w.LeadHours == nil {
		return time.Time{}, false
	}
	return w.EndsAt(knownAt).Add(-time.Duration(*w.LeadHours) * time.Hour), true
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

// ErrNoSuchProduct is returned where a window names a product nobody declared.
var ErrNoSuchProduct = errors.New("no product goes by that name")

// windowSaid checks what a window states before any of it is stored.
func windowSaid(said WindowSaid) (WindowSaid, error) {
	name, err := nameSaid(said.Name, said.Hours)
	if err != nil {
		return said, err
	}
	said.Name = name
	if said.LeadHours != nil {
		// Zero reads as unset everywhere, so a lead of none is written by
		// leaving it out rather than stored as a notice at the end itself.
		if *said.LeadHours <= 0 {
			return said, errors.New("a warning comes at least an hour before the end")
		}
		// A warning at or before the moment the window opens says nothing the
		// notice raised when the record stands has not already said.
		if *said.LeadHours >= said.Hours {
			return said, errors.New("a warning comes before the end and after the window opens")
		}
	}
	return said, nil
}

// nameSaid checks a name and a length.
func nameSaid(name string, hours int) (string, error) {
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
	if len(windows) == 0 {
		return windows, nil
	}
	ids := make([]int64, 0, len(windows))
	for _, window := range windows {
		ids = append(ids, window.ID)
	}
	var limits []struct {
		WindowID  int64  `bun:"window_id"`
		ProductID int64  `bun:"product_id"`
		Product   string `bun:"product"`
	}
	err = s.db.NewSelect().
		TableExpr(`"obligation_window_product" AS "owp"`).
		Join(`JOIN "product" AS "p" ON p.id = owp.product_id`).
		ColumnExpr(`owp.window_id AS "window_id"`).
		ColumnExpr(`owp.product_id AS "product_id"`).
		ColumnExpr(`p.name AS "product"`).
		Where("owp.window_id IN (?)", bun.List(ids)).
		Order("p.name ASC").
		Scan(ctx, &limits)
	if err != nil {
		return nil, fmt.Errorf("read which products the windows apply to: %w", err)
	}
	at := make(map[int64]int, len(windows))
	for i, window := range windows {
		at[window.ID] = i
	}
	for _, limit := range limits {
		window := &windows[at[limit.WindowID]]
		window.Products = append(window.Products, limit.ProductID)
		window.ProductNames = append(window.ProductNames, limit.Product)
	}
	return windows, nil
}

// productsNamed resolves the names a window is limited to, inside the write
// that stores them.
//
// Refused whole on a name nobody declared: a window that silently applied to
// fewer products than the administrator named would be quiet about the one
// they meant.
func productsNamed(ctx context.Context, tx bun.IDB, names []string) ([]int64, []string, error) {
	if len(names) == 0 {
		return nil, nil, nil
	}
	folded := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		folded = append(folded, name)
	}
	var found []struct {
		ID   int64  `bun:"id"`
		Name string `bun:"name"`
	}
	if err := tx.NewSelect().
		TableExpr(`"product" AS "p"`).
		ColumnExpr(`p.id AS "id"`).
		ColumnExpr(`p.name AS "name"`).
		Where("p.name IN (?)", bun.List(folded)).
		Order("p.name ASC").
		Scan(ctx, &found); err != nil {
		return nil, nil, fmt.Errorf("read the products a window names: %w", err)
	}
	known := map[string]bool{}
	ids := make([]int64, 0, len(found))
	kept := make([]string, 0, len(found))
	for _, product := range found {
		known[product.Name] = true
		ids = append(ids, product.ID)
		kept = append(kept, product.Name)
	}
	for _, name := range folded {
		if !known[name] {
			return nil, nil, fmt.Errorf("%w: %q", ErrNoSuchProduct, name)
		}
	}
	return ids, kept, nil
}

// limit replaces the products a window applies to.
func limit(ctx context.Context, tx bun.IDB, windowID int64, products []int64) error {
	if _, err := tx.NewDelete().Model((*WindowProduct)(nil)).
		Where("window_id = ?", windowID).Exec(ctx); err != nil {
		return fmt.Errorf("clear the products a window applies to: %w", err)
	}
	if len(products) == 0 {
		return nil
	}
	rows := make([]WindowProduct, 0, len(products))
	for _, id := range products {
		rows = append(rows, WindowProduct{WindowID: windowID, ProductID: id})
	}
	if _, err := tx.NewInsert().Model(&rows).Exec(ctx); err != nil {
		return fmt.Errorf("limit a window to its products: %w", err)
	}
	return nil
}

// DeclareWindow adds a window this deployment counts.
//
// An administrator's act, and one the trail records: a window decides what
// every incident is watched against from now on, which is the layer a setting
// sits in.
func (s *Store) DeclareWindow(ctx context.Context, subject access.Subject,
	said WindowSaid) (*Window, error) {

	if !subject.Admin || subject.Kind != access.Person {
		return nil, access.Denied("declare a window")
	}
	said, err := windowSaid(said)
	if err != nil {
		return nil, err
	}
	window := new(Window)
	err = s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		products, names, err := productsNamed(ctx, tx, said.Products)
		if err != nil {
			return err
		}
		live := folded(said.Name)
		*window = Window{
			Name: said.Name, Hours: said.Hours, LeadHours: said.LeadHours,
			DeclaredBy: subject.ID,
			DeclaredAt: s.now().Truncate(time.Microsecond), LiveName: &live,
		}
		if _, err := tx.NewInsert().Model(window).Exec(ctx); err != nil {
			if database.IsDuplicate(err) {
				return ErrWindowNamed
			}
			return fmt.Errorf("declare a window: %w", err)
		}
		if err := limit(ctx, tx, window.ID, products); err != nil {
			return err
		}
		window.Products, window.ProductNames = products, names
		return noteWindow(ctx, tx, subject, said.Name, nil, describe(*window))
	})
	if err != nil {
		return nil, err
	}
	return window, nil
}

// ChangeWindow restates a window in force: its name, how long it runs, its
// warning, and the products it applies to.
//
// Every incident's end moves with it, because an end is worked out from the
// window as it stands rather than stored. A notice already recorded against
// the window keeps pointing at it.
func (s *Store) ChangeWindow(ctx context.Context, subject access.Subject, id int64,
	said WindowSaid) (*Window, error) {

	if !subject.Admin || subject.Kind != access.Person {
		return nil, access.Denied("change a window")
	}
	said, err := windowSaid(said)
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
		var before []string
		if err := tx.NewSelect().
			TableExpr(`"obligation_window_product" AS "owp"`).
			Join(`JOIN "product" AS "p" ON p.id = owp.product_id`).
			ColumnExpr("p.name").
			Where("owp.window_id = ?", id).
			Order("p.name ASC").
			Scan(ctx, &before); err != nil {
			return fmt.Errorf("read which products the window applies to: %w", err)
		}
		window.ProductNames = before
		was := describe(*window)
		products, names, err := productsNamed(ctx, tx, said.Products)
		if err != nil {
			return err
		}
		live := folded(said.Name)
		res, err := tx.NewUpdate().Model((*Window)(nil)).
			Set("name = ?", said.Name).
			Set("length_hours = ?", said.Hours).
			Set("lead_hours = ?", said.LeadHours).
			Set("live_name = ?", live).
			Where("id = ?", id).
			// Still in force when this lands. A retirement committed since the
			// read above leaves nothing to change, and a trail row saying it
			// changed would be false.
			Where("retired_at IS NULL").
			Exec(ctx)
		if err != nil {
			if database.IsDuplicate(err) {
				return ErrWindowNamed
			}
			return fmt.Errorf("change a window: %w", err)
		}
		changed, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("change a window: %w", err)
		}
		if changed == 0 {
			return ErrNoSuchWindow
		}
		if err := limit(ctx, tx, id, products); err != nil {
			return err
		}
		window.Name, window.Hours, window.LeadHours, window.LiveName =
			said.Name, said.Hours, said.LeadHours, &live
		window.Products, window.ProductNames = products, names
		return noteWindow(ctx, tx, subject, said.Name, was, describe(*window))
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
		var products []string
		if err := tx.NewSelect().
			TableExpr(`"obligation_window_product" AS "owp"`).
			Join(`JOIN "product" AS "p" ON p.id = owp.product_id`).
			ColumnExpr("p.name").
			Where("owp.window_id = ?", id).
			Order("p.name ASC").
			Scan(ctx, &products); err != nil {
			return fmt.Errorf("read which products the window applies to: %w", err)
		}
		window.ProductNames = products
		return noteWindow(ctx, tx, subject, window.Name, describe(*window), nil)
	})
}

// writing runs do inside one transaction, retried as a whole.
func (s *Store) writing(ctx context.Context,
	do func(ctx context.Context, tx bun.IDB) error) error {

	return database.Within(ctx, s.db, do)
}

// describe is a window as the trail records it: its length, its warning and
// the products it is limited to.
func describe(w Window) *string {
	text := strconv.Itoa(w.Hours) + "h"
	if w.LeadHours != nil {
		text += ", warned " + strconv.Itoa(*w.LeadHours) + "h before"
	}
	if len(w.ProductNames) > 0 {
		text += ", for " + strings.Join(w.ProductNames, ", ")
	}
	return trail.Said(text, true)
}

// noteWindow writes a change to a window into the administrative trail, in
// the transaction that makes it.
func noteWindow(ctx context.Context, tx bun.IDB, subject access.Subject, name string,
	was, became *string) error {

	return trail.NewStore(tx).Record(ctx, subject, trail.Setting,
		"Obligation window "+name, was, became)
}
