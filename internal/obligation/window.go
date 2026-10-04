// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// Window is a period a deployment says it answers within, counted from the
// moment an attack became known or from the first notice naming another
// window.
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
	// FromID is the window whose first notice on an incident this one counts
	// from, or nil where it counts from the moment the attack became known.
	FromID *int64 `bun:"from_window_id"`
	// FromName is that window's name.
	FromName string `bun:"-"`
	// FromFix says the window counts from the earliest release date stated
	// for a release the record names as carrying the fix. Never set beside
	// FromID.
	FromFix bool `bun:"from_fix,notnull"`

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
	// From is the window in force whose first notice on an incident this one
	// counts from, or nil to count from the moment the attack became known.
	From *int64
	// FromFix counts the window from the earliest release date stated for a
	// release the record names as carrying the fix. Refused beside From.
	FromFix bool
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

// Covers is whether this window applies to every product the other does. A
// window counting from another's notice is held to it: a notice can name a
// window only on a product the window applies to, so a product outside it
// would hold a window that never starts.
func (w Window) Covers(other Window) bool {
	if len(w.Products) == 0 {
		return true
	}
	if len(other.Products) == 0 {
		return false
	}
	for _, id := range other.Products {
		if !w.AppliesTo(id) {
			return false
		}
	}
	return true
}

// NearAt is when the second notice for an incident is raised, where the
// window names a lead time, for a window that started at this moment.
func (w Window) NearAt(start time.Time) (time.Time, bool) {
	if w.LeadHours == nil {
		return time.Time{}, false
	}
	return w.EndsAt(start).Add(-time.Duration(*w.LeadHours) * time.Hour), true
}

// Length is how long the window runs.
func (w Window) Length() time.Duration { return time.Duration(w.Hours) * time.Hour }

// EndsAt is when the window counted from this moment closes.
func (w Window) EndsAt(start time.Time) time.Time { return start.Add(w.Length()) }

// LongestHours bounds a window at a year. A window longer than that is not
// one anybody is watched against, and the bound keeps the arithmetic of an
// end well inside what every engine stores.
const LongestHours = 24 * 366

// ErrNoSuchWindow is returned where a window is missing or retired.
var ErrNoSuchWindow = refusal.New("no window in force goes by that")

// ErrWindowNamed is returned where a window in force already has the name.
var ErrWindowNamed = refusal.New("a window in force already has that name")

// ErrCountedFrom is returned where a window another window in force counts
// from would be retired. The refusal names that window.
var ErrCountedFrom = refusal.New("another window in force counts from this one")

// holdWindows takes every window in force for the rest of the transaction,
// before anything is read.
//
// What one window counts from is a rule over several rows: the window it
// counts from is in force, covers its products, and leads back to no loop,
// and nothing counting from a window is left uncovered by changing or
// retiring it. Each write here checks those by reading rows it does not
// write, and a transaction is not a lock (`DESIGN-database.md` § Reads a
// write depends on). So every declaration counting from another window, every
// change and every retirement first writes every window in force, unchanged.
// Two of them wait for each other, and the second reads what the first
// committed: MySQL and MariaDB fix the snapshot at the first plain read, which
// comes after this. The windows in force are a handful, so the whole set is
// held rather than the rows one act happens to walk: a loop closed by two
// changes can pass through no row either one names.
func holdWindows(ctx context.Context, tx bun.IDB) error {
	if _, err := tx.NewUpdate().Model((*Window)(nil)).
		Set("live_name = live_name").
		Where("retired_at IS NULL").
		Exec(ctx); err != nil {
		return fmt.Errorf("hold the windows in force: %w", err)
	}
	return nil
}

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
var ErrNoSuchProduct = refusal.New("no product goes by that name")

// windowSaid checks what a window states before any of it is stored.
func windowSaid(said WindowSaid) (WindowSaid, error) {
	name, err := nameSaid(said.Name, said.Hours)
	if err != nil {
		return said, err
	}
	said.Name = name
	if said.FromFix && said.From != nil {
		return said, refusal.New("a window counts from one moment: a notice for another window, " +
			"or the release of the fix, not both")
	}
	if said.LeadHours != nil {
		// Zero reads as unset everywhere, so a lead of none is written by
		// leaving it out rather than stored as a notice at the end itself.
		if *said.LeadHours <= 0 {
			return said, refusal.New("a warning comes at least an hour before the end")
		}
		// A warning at or before the moment the window opens says nothing the
		// notice raised when the record stands has not already said.
		if *said.LeadHours >= said.Hours {
			return said, refusal.New("a warning comes before the end and after the window opens")
		}
	}
	return said, nil
}

// nameSaid checks a name and a length.
func nameSaid(name string, hours int) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", refusal.New("a window needs a name")
	}
	if utf8.RuneCountInString(name) > database.NameWidth {
		return "", refusal.Errorf("a window's name is at most %d characters", database.NameWidth)
	}
	// Zero reads as unset everywhere, so it is refused rather than stored as
	// a window that closes the moment it opens.
	if hours <= 0 {
		return "", refusal.New("a window runs for at least an hour")
	}
	if hours > LongestHours {
		return "", refusal.Errorf("a window runs for at most %d hours", LongestHours)
	}
	return name, nil
}

// Windows is every window in force this subject may read, shortest first: the
// order they close in for any one incident.
//
// A window limited to products the subject may not know exist is left out,
// and the products a window names are narrowed to the ones they may: the list
// of products is itself a statement about what an organization ships. The
// deployment's own passes read as a subject that knows every product.
func (s *Store) Windows(ctx context.Context, subject access.Subject) ([]Window, error) {
	windows, err := s.inForce(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Window, 0, len(windows))
	for _, window := range windows {
		if shown, ok := window.As(subject); ok {
			out = append(out, shown)
		}
	}
	return out, nil
}

// As is a window as this subject may read it, and whether they may read it at
// all.
func (w Window) As(subject access.Subject) (Window, bool) {
	if len(w.Products) == 0 {
		return w, true
	}
	shown := w
	shown.Products, shown.ProductNames = nil, nil
	for i, id := range w.Products {
		if subject.Sees(id) {
			shown.Products = append(shown.Products, id)
			shown.ProductNames = append(shown.ProductNames, w.ProductNames[i])
		}
	}
	return shown, len(shown.Products) > 0
}

// inForce is every window in force, whole.
func (s *Store) inForce(ctx context.Context) ([]Window, error) {
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
	windows, err = withLimits(ctx, s.db, windows)
	if err != nil {
		return nil, err
	}
	return withFrom(ctx, s.db, windows)
}

// withFrom fills in the name of the window each window counts from, which the
// window row itself does not carry. Read as the window stands: what a window
// counts from is never retired while it does.
func withFrom(ctx context.Context, db bun.IDB, windows []Window) ([]Window, error) {
	wanted := map[int64]bool{}
	for _, window := range windows {
		if window.FromID != nil {
			wanted[*window.FromID] = true
		}
	}
	if len(wanted) == 0 {
		return windows, nil
	}
	ids := make([]int64, 0, len(wanted))
	for id := range wanted {
		ids = append(ids, id)
	}
	var named []Window
	if err := db.NewSelect().Model(&named).Column("ow.id", "ow.name").
		Where("ow.id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the windows others count from: %w", err)
	}
	names := make(map[int64]string, len(named))
	for _, window := range named {
		names[window.ID] = window.Name
	}
	for i, window := range windows {
		if window.FromID != nil {
			windows[i].FromName = names[*window.FromID]
		}
	}
	return windows, nil
}

// countsFrom checks the window one declared or changed would count from,
// inside the write that stores it, and returns its name.
//
// It is a window in force that applies to every product this one does. It is
// not this window, and nothing it counts from, followed back, is this window:
// a loop of windows each waiting on another's notice never starts.
func countsFrom(ctx context.Context, tx bun.IDB, self int64, from int64,
	window Window) (string, error) {
	anchor, err := inForce(ctx, tx, from)
	if errors.Is(err, ErrNoSuchWindow) {
		return "", refusal.New("a window counts from a window in force, or from when the attack became known")
	}
	if err != nil {
		return "", err
	}
	if !anchor.Covers(window) {
		return "", refusal.Errorf("%q does not apply to every product this window does, "+
			"so a notice for it could not start this one everywhere", anchor.Name)
	}
	seen := map[int64]bool{}
	for at := anchor; ; {
		if at.ID == self {
			return "", refusal.New("a window cannot count from itself, or from a window counting from it")
		}
		if at.FromID == nil || seen[at.ID] {
			break
		}
		seen[at.ID] = true
		next := new(Window)
		if err := tx.NewSelect().Model(next).Where("ow.id = ?", *at.FromID).Scan(ctx); err != nil {
			return "", fmt.Errorf("read the window another counts from: %w", err)
		}
		at = next
	}
	return anchor.Name, nil
}

// dependents is every window in force counting from this one, with the
// products each is limited to.
func dependents(ctx context.Context, tx bun.IDB, id int64) ([]Window, error) {
	var windows []Window
	if err := tx.NewSelect().Model(&windows).
		Where("ow.from_window_id = ?", id).Where("ow.retired_at IS NULL").
		Order("ow.id ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the windows counting from a window: %w", err)
	}
	return withLimits(ctx, tx, windows)
}

// withLimits fills in the products each window is limited to, which the
// window row itself does not carry.
func withLimits(ctx context.Context, db bun.IDB, windows []Window) ([]Window, error) {
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
	err := db.NewSelect().
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
	for _, typed := range names {
		name := catalog.Matching(typed)
		// A blank name is a name nobody declared, refused like any other:
		// dropped, a list holding only blanks declares a window over every
		// product.
		if name == "" {
			return nil, nil, fmt.Errorf("%w: %q", ErrNoSuchProduct, typed)
		}
		if seen[name] {
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

	if err := administers(subject, "declare a window"); err != nil {
		return nil, err
	}
	said, err := windowSaid(said)
	if err != nil {
		return nil, err
	}
	window := new(Window)
	err = s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		if said.From != nil {
			if err := holdWindows(ctx, tx); err != nil {
				return err
			}
		}
		products, names, err := productsNamed(ctx, tx, said.Products)
		if err != nil {
			return err
		}
		live := folded(said.Name)
		*window = Window{
			Name: said.Name, Hours: said.Hours, LeadHours: said.LeadHours,
			DeclaredBy: subject.ID,
			DeclaredAt: s.now().Truncate(time.Microsecond), LiveName: &live,
			FromID: said.From, FromFix: said.FromFix, Products: products, ProductNames: names,
		}
		if said.From != nil {
			if window.FromName, err = countsFrom(ctx, tx, 0, *said.From, *window); err != nil {
				return err
			}
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

	if err := administers(subject, "change a window"); err != nil {
		return nil, err
	}
	said, err := windowSaid(said)
	if err != nil {
		return nil, err
	}
	window := new(Window)
	err = s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		if err := holdWindows(ctx, tx); err != nil {
			return err
		}
		before, err := inForce(ctx, tx, id)
		if err != nil {
			return err
		}
		named, err := withFrom(ctx, tx, []Window{*before})
		if err != nil {
			return err
		}
		*window = named[0]
		was := describe(*window)
		products, names, err := productsNamed(ctx, tx, said.Products)
		if err != nil {
			return err
		}
		after := *window
		after.Products, after.ProductNames, after.FromID, after.FromName =
			products, names, said.From, ""
		if said.From != nil {
			if after.FromName, err = countsFrom(ctx, tx, id, *said.From, after); err != nil {
				return err
			}
		}
		// Every window counting from this one still applies only where this
		// one does.
		counting, err := dependents(ctx, tx, id)
		if err != nil {
			return err
		}
		for _, other := range counting {
			if !after.Covers(other) {
				return refusal.Errorf("%q counts from this window and applies to a product "+
					"this one would not", other.Name)
			}
		}
		live := folded(said.Name)
		res, err := tx.NewUpdate().Model((*Window)(nil)).
			Set("name = ?", said.Name).
			Set("length_hours = ?", said.Hours).
			Set("lead_hours = ?", said.LeadHours).
			Set("live_name = ?", live).
			Set("from_window_id = ?", said.From).
			Set("from_fix = ?", said.FromFix).
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
		window.FromID, window.FromName = after.FromID, after.FromName
		window.FromFix = said.FromFix
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
	if err := administers(subject, "retire a window"); err != nil {
		return err
	}
	return s.writing(ctx, func(ctx context.Context, tx bun.IDB) error {
		if err := holdWindows(ctx, tx); err != nil {
			return err
		}
		window, err := inForce(ctx, tx, id)
		if err != nil {
			return err
		}
		counting, err := dependents(ctx, tx, id)
		if err != nil {
			return err
		}
		if len(counting) > 0 {
			return fmt.Errorf("%w: %q. Change or retire it first", ErrCountedFrom, counting[0].Name)
		}
		named, err := withFrom(ctx, tx, []Window{*window})
		if err != nil {
			return err
		}
		window = &named[0]
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
		return noteWindow(ctx, tx, subject, window.Name, describe(*window), nil)
	})
}

// inForce reads a window still in force, with the products it is limited to
// and their names, which is what the trail says a window was.
func inForce(ctx context.Context, tx bun.IDB, id int64) (*Window, error) {
	window := new(Window)
	if err := tx.NewSelect().Model(window).
		Where("ow.id = ?", id).Where("ow.retired_at IS NULL").
		Scan(ctx); err != nil {
		if database.IsNoRows(err) {
			return nil, ErrNoSuchWindow
		}
		return nil, fmt.Errorf("read the window: %w", err)
	}
	limited, err := withLimits(ctx, tx, []Window{*window})
	if err != nil {
		return nil, err
	}
	return &limited[0], nil
}

// administers refuses anybody but a signed-in administrator the act named.
func administers(subject access.Subject, act string) error {
	if !subject.Admin || subject.Kind != access.Person {
		return access.Denied(act)
	}
	return nil
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
	if w.FromID != nil {
		text += " from the first notice for " + w.FromName
	}
	if w.FromFix {
		text += " from the release of the fix"
	}
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
