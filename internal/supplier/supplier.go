// Package supplier fetches the security advisories a supplier publishes and
// records them as evidence.
//
// A supplier's advisory already arrives by upload. That is somebody deciding
// one document is worth reading, and it does not scale to a publisher who
// issues hundreds a year: which of them is about a component a build here ships
// is not knowable until the document has been read. So the deliberate act moves
// up one level — an administrator names the publisher, and this reads what they
// publish from then on.
//
// Nothing it reads decides anything. What arrives lands in the same evidence
// layer an uploaded document lands in: shown beside a finding, offered as a
// prefill, and never standing as our judgment by itself (REQ-31). A pass
// running on a schedule makes that easier to violate by accident than an upload
// does, because nobody is watching each document arrive.
//
// Only what some product here ships. A publisher's feed is about their whole
// catalog, and one real advisory about a kernel carries 95,139 claims. Taken
// whole, a deployment would store a supplier's catalog rather than evidence
// about its own. So a fetched document is narrowed to the components the
// product actually holds before anything is written, which is the one rule this
// path has that the upload path does not — an upload is one document somebody
// chose, and this is every document a publisher issues.
//
// Off unless configured. A deployment that names no supplier reaches nothing,
// and one that cannot reach out loses a publisher's own judgment as evidence.
// What a scan reports is unaffected: nothing on that path leaves this
// deployment (REQ-12).
package supplier

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Source is a supplier this deployment fetches advisories from.
type Source struct {
	bun.BaseModel `bun:"table:advisory_source,alias:sp"`

	ID        int64 `bun:"id,pk,autoincrement"`
	ProductID int64 `bun:"product_id,notnull"`
	// Name is what this supplier is matched by, lowered, and Display is the
	// spelling somebody typed. Two columns rather than one, because a name
	// people type is matched without regard to capitals and the four engines
	// fold differently — a value normalized on the way in compares the same
	// under any of them.
	Name    string `bun:"name,notnull"`
	Display string `bun:"display_name,notnull"`
	// URL is where the supplier describes what they publish. Beside the name
	// rather than instead of it, because a publisher that moves its site is
	// the same supplier and the claims already recorded name them.
	URL string `bun:"url,notnull"`
	// CaughtUpTo and CaughtUpMark are how far through what this publisher
	// lists the source has been read: the moment, and the digest of the
	// address read at that moment. Absent until the first pass.
	//
	// A pair rather than a moment. A publisher stamps a batch of documents
	// with one moment, and a date-only stamp gives a whole day the same one —
	// so a cycle that stopped inside such a group would leave the mark on that
	// moment and skip the rest of the group for ever.
	CaughtUpTo   *time.Time `bun:"caught_up_to"`
	CaughtUpMark string     `bun:"caught_up_mark"`
	// FetchedAt is when a pass last tried this supplier, ReachedAt when one
	// last succeeded, and Failed what stopped the last one.
	//
	// Two moments, because an attempt that failed still happened: one moment
	// moving on every attempt reads as a supplier answering fine right up to
	// the failure it is reporting, and how long one has been unreachable is
	// the gap between them.
	FetchedAt *time.Time `bun:"fetched_at"`
	ReachedAt *time.Time `bun:"reached_at"`
	Failed    string     `bun:"failed"`
	CreatedBy int64      `bun:"created_by,notnull"`
	CreatedAt time.Time  `bun:"created_at,notnull"`
	RetiredAt *time.Time `bun:"retired_at"`
}

// MostName and MostURL are the widths a source is recorded in.
//
// Refused rather than shortened. The name is half of what identifies a source,
// so two shortened to one length become one supplier and withdrawing either
// withdraws both; a shortened address is a request somewhere nobody meant. The
// name is the width the column holds, and on two of the four engines a value
// past it is truncated rather than refused outside strict mode.
const (
	MostName = database.NameWidth
	MostURL  = 1000
)

// MostReason bounds what is kept of why a supplier could not be read.
//
// The text carries a publisher's own address and a server's own reason phrase,
// both of which they choose and neither of which is bounded by anything they
// have agreed to. A sentence is what an operator reads; a megabyte is a write
// that fails on two of the four engines, which would leave the attempt
// unrecorded and the supplier fetched again on the next wake.
const MostReason = 400

// Store reads and writes the suppliers this deployment fetches from.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// At fixes the clock, for a test that asks what happens at a given moment.
func (s *Store) At(now func() time.Time) *Store { return &Store{db: s.db, now: now} }

// matching is the name a supplier is found by.
//
// Lowered on the way in rather than compared loosely on the way out. The four
// engines default to different collations, so asking one to fold makes whether
// two spellings are one supplier depend on which engine is running; a lowered
// value compares the same under any of them, and the unique constraint means
// the same thing everywhere.
func matching(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// Mark is the digest of an address, which is half of how far a source has been
// read.
//
// A digest rather than the address, so that ordering two marks is a comparison
// over lower-case hexadecimal. Every engine orders those the same way whatever
// its collation, which a comparison over addresses themselves does not — and
// the ordering only has to be the same on both sides, never meaningful.
func Mark(address string) string {
	sum := sha256.Sum256([]byte(address))
	return hex.EncodeToString(sum[:])
}

// ErrNameTaken says a supplier is already read under that name.
var ErrNameTaken = errors.New("a supplier is already read under that name")

// administering refuses anybody but an administrator.
//
// Configuring a supplier admits a third party's judgment into this deployment's
// evidence and points it at an address of their choosing. It is a deployment
// decision rather than a product one, held by the same person who configures
// where notifications go.
func administering(subject access.Subject, what string) error {
	if !subject.Admin || subject.Kind != access.Person {
		return access.Denied(what)
	}
	return nil
}

// inUse narrows to the sources of a product that is still in use.
//
// A product taken out of use offers nothing and accepts no scan, and nothing
// lists it — so a supplier configured against one goes on being fetched and
// recorded into, with no screen left that could withdraw it.
func inUse(q *bun.SelectQuery) *bun.SelectQuery {
	return q.Join(`JOIN "product" AS "pr" ON pr.id = sp.product_id`).
		Where("pr.retired_at IS NULL")
}

// Due is every supplier still configured that has not been tried since before.
//
// Read by the pass, which answers nobody: it carries the deployment's own
// subject because there is no person behind a background cycle, and what it
// asks for is the list it is about to work through.
//
// One never tried is due whatever the moment, which is what makes a supplier
// named this morning read this afternoon rather than tomorrow.
func (s *Store) Due(ctx context.Context, subject access.Subject, before time.Time) ([]Source, error) {
	if !subject.Unnarrowed() {
		if err := administering(subject, "read which suppliers are fetched from"); err != nil {
			return nil, err
		}
	}
	var rows []Source
	q := s.db.NewSelect().Model(&rows).
		Where("sp.retired_at IS NULL").
		Where(`"sp"."fetched_at" IS NULL OR "sp"."fetched_at" < ?`,
			before.UTC().Truncate(time.Microsecond)).
		// Longest untried first, and one never tried before the rest. Nothing
		// bounds how many suppliers a cycle takes, so the order is what keeps
		// one that is slow from being the only one ever reached.
		OrderExpr(`CASE WHEN "sp"."fetched_at" IS NULL THEN 0 ELSE 1 END`).
		OrderExpr(`"sp"."fetched_at"`).OrderExpr(`"sp"."id"`)
	if err := inUse(q).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which suppliers are fetched from: %w", err)
	}
	return rows, nil
}

// Standing reads one source back as it is now.
//
// Asked inside the transaction that records what a document said, because a
// pass takes minutes and a supplier withdrawn during one is a request leaving
// this deployment that somebody thought they had stopped. Answers nothing where
// the source has been withdrawn or its product taken out of use.
func (s *Store) Standing(ctx context.Context, db bun.IDB, id int64) (*Source, error) {
	row := new(Source)
	q := db.NewSelect().Model(row).Where("sp.id = ?", id).Where("sp.retired_at IS NULL")
	switch err := inUse(q).Scan(ctx); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read whether that supplier is still configured: %w", err)
	}
	return row, nil
}

// For is every supplier configured against one product.
func (s *Store) For(ctx context.Context, subject access.Subject, productID int64) ([]Source, error) {
	if err := administering(subject, "read which suppliers are fetched from"); err != nil {
		return nil, err
	}
	var rows []Source
	if err := s.db.NewSelect().Model(&rows).
		Where("sp.product_id = ?", productID).
		Where("sp.retired_at IS NULL").
		Order("name").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which suppliers are fetched from: %w", err)
	}
	return rows, nil
}

// Add records a supplier to fetch advisories from, for one product.
//
// A name that was retired is taken up again rather than refused. The row stays
// when a source is retired, because what was taken from where is a question
// asked afterwards, and the name is unique across retired rows too — so
// inserting a second under the same name would fail on a row nothing lists,
// with a message about a supplier nobody can see.
//
// Taking one up again at the same address keeps how far it had been read, so
// it takes what was issued while it was away and nothing it already read. How
// far back that reaches is bounded by the history window a new supplier is
// read from. Taken up at another address, it starts where a new one does.
func (s *Store) Add(ctx context.Context, subject access.Subject, productID int64,
	name, address string) (*Source, error) {

	if err := administering(subject, "configure which suppliers are fetched from"); err != nil {
		return nil, err
	}
	typed := strings.TrimSpace(name)
	address = strings.TrimSpace(address)
	if typed == "" || address == "" {
		return nil, fmt.Errorf("a supplier needs a name and an address")
	}
	if utf8.RuneCountInString(typed) > MostName {
		return nil, fmt.Errorf("that name is longer than the %d characters this records",
			MostName)
	}
	if utf8.RuneCountInString(address) > MostURL {
		return nil, fmt.Errorf("that address is longer than the %d characters this records",
			MostURL)
	}
	// Judged here as well as at the request, so a second caller cannot store
	// an address the pass will refuse only when it comes to fetch.
	if err := Reachable(address); err != nil {
		return nil, err
	}
	// A product taken out of use accepts no scan, so what a supplier would be
	// read against is a build list nothing adds to. Refused here the way
	// filing a scan against one is, rather than leaving a source nothing
	// lists and nothing can withdraw.
	switch live, err := s.productInUse(ctx, productID); {
	case err != nil:
		return nil, err
	case !live:
		return nil, fmt.Errorf("that product is out of use, and a supplier is read " +
			"against what a product ships")
	}
	folded := matching(typed)
	now := s.now().UTC().Truncate(time.Microsecond)
	row := &Source{
		ProductID: productID, Name: folded, Display: typed, URL: address,
		CreatedBy: subject.ID, CreatedAt: now,
	}
	res, err := s.db.NewUpdate().Model((*Source)(nil)).
		// The mark is kept only where the address is the one it was read
		// at. An address never read has nothing behind it this supplier has
		// seen, so it starts where a new one does. Ahead of the address
		// itself, because one engine applies the assignments in order and
		// would otherwise compare against the value just written.
		Set(`"caught_up_to" = CASE WHEN "url" = ? THEN "caught_up_to" END`, row.URL).
		Set(`"caught_up_mark" = CASE WHEN "url" = ? THEN "caught_up_mark" ELSE '' END`, row.URL).
		Set("retired_at = ?", nil).
		Set("display_name = ?", row.Display).
		Set("url = ?", row.URL).
		Set("created_by = ?", row.CreatedBy).
		Set("created_at = ?", row.CreatedAt).
		// Cleared, so a failure from before it was withdrawn is not read as
		// one by the pass that has not run yet.
		Set("fetched_at = ?", nil).
		Set("reached_at = ?", nil).
		Set("failed = ?", "").
		Where("product_id = ?", productID).
		Where("name = ?", folded).
		Where("retired_at IS NOT NULL").
		Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("take that supplier up again: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return nil, fmt.Errorf("take that supplier up again: %w", err)
	}
	if n > 0 {
		if err := s.db.NewSelect().Model(row).
			Where("sp.product_id = ?", productID).Where("sp.name = ?", folded).
			Limit(1).Scan(ctx); err != nil {
			return nil, fmt.Errorf("read that supplier back: %w", err)
		}
		return row, nil
	}
	if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
		// A name already in use is somebody adding the same supplier twice,
		// which is an answer rather than a fault: the row it collides with is
		// one they can see.
		if database.IsDuplicate(err) {
			return nil, fmt.Errorf("%w: %q", ErrNameTaken, typed)
		}
		return nil, fmt.Errorf("record that supplier: %w", err)
	}
	return row, nil
}

// productInUse reports whether a product is still offered.
func (s *Store) productInUse(ctx context.Context, productID int64) (bool, error) {
	n, err := s.db.NewSelect().TableExpr(`"product" AS "pr"`).
		Where("pr.id = ?", productID).Where("pr.retired_at IS NULL").Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether that product is in use: %w", err)
	}
	return n > 0, nil
}

// Retire stops fetching from a supplier.
//
// What they have already said stays standing. A publisher's claims are evidence
// somebody may have granted an approval on the strength of, and withdrawing the
// address we read them from does not make them unsaid.
func (s *Store) Retire(ctx context.Context, subject access.Subject, productID int64,
	name string) error {

	if err := administering(subject, "configure which suppliers are fetched from"); err != nil {
		return err
	}
	res, err := s.db.NewUpdate().Model((*Source)(nil)).
		Set("retired_at = ?", s.now().UTC().Truncate(time.Microsecond)).
		Where("product_id = ?", productID).
		Where("name = ?", matching(name)).
		Where("retired_at IS NULL").Exec(ctx)
	if err != nil {
		return fmt.Errorf("stop fetching from that supplier: %w", err)
	}
	// A source believed retired that was not goes on fetching, which is a
	// request leaving this deployment that somebody thought they had stopped.
	// Answered as success, the only thing that would say otherwise is reading
	// the list back.
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("stop fetching from that supplier: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("no supplier is fetched from under the name %q: %w",
			name, access.ErrNothingMatched)
	}
	return nil
}

// Reached records what one attempt at a supplier found.
//
// Written whether or not anything came back. An attempt that failed still
// happened, and how long a publisher has been unreachable is the gap between
// the last attempt and the last one that worked — which is a fact nothing else
// in this deployment holds.
//
// The mark moves forward only, and it is the whole pair that is compared. A
// publisher that revises an old document stamps it with the moment of the
// revision, so an entry behind the mark is one already taken — and a mark that
// could go backwards would make a publisher who re-stamped one document replay
// their whole history.
//
// The mark is conditional and the two moments are not. Written as one condition
// on the statement, a mark that did not advance took the record of the attempt
// with it, and the supplier was tried again on every wake.
func (s *Store) Reached(ctx context.Context, id int64, at time.Time, mark string,
	failed error) error {

	now := s.now().UTC().Truncate(time.Microsecond)
	update := s.db.NewUpdate().Model((*Source)(nil)).
		Set("fetched_at = ?", now).
		Where("id = ?", id)
	if failed != nil {
		update = update.Set("failed = ?", bound.HeadRunes(failed.Error(), MostReason))
	} else {
		update = update.Set("failed = ?", "").Set("reached_at = ?", now)
	}
	if !at.IsZero() {
		moment := at.UTC().Truncate(time.Microsecond)
		// A CASE rather than a condition on the statement, so that a mark
		// which does not advance leaves the two moments written. The pair is
		// compared in the order it is read in: the moment, then the digest of
		// the address, which is hexadecimal and so orders the same on every
		// engine.
		update = update.
			Set(`"caught_up_to" = CASE WHEN `+ahead+` THEN ? ELSE "caught_up_to" END`,
				moment, moment, mark, moment).
			Set(`"caught_up_mark" = CASE WHEN `+ahead+` THEN ? ELSE "caught_up_mark" END`,
				moment, moment, mark, mark)
	}
	if _, err := update.Exec(ctx); err != nil {
		return fmt.Errorf("record what came back from that supplier: %w", err)
	}
	return nil
}

// CaughtUp records how far a pass read without saying the supplier is done.
//
// For a pass that stopped at its bound rather than because there was nothing
// left. The mark moves so the next wake starts after what was read, and the two
// moments are left alone so the supplier stays due: the bound is per wake and
// the interval is a day, so a publisher issuing more in a day than one pass
// takes would otherwise fall further behind every day.
func (s *Store) CaughtUp(ctx context.Context, id int64, at time.Time, mark string) error {
	if at.IsZero() {
		return nil
	}
	moment := at.UTC().Truncate(time.Microsecond)
	_, err := s.db.NewUpdate().Model((*Source)(nil)).
		Set(`"caught_up_to" = CASE WHEN `+ahead+` THEN ? ELSE "caught_up_to" END`,
			moment, moment, mark, moment).
		Set(`"caught_up_mark" = CASE WHEN `+ahead+` THEN ? ELSE "caught_up_mark" END`,
			moment, moment, mark, mark).
		Set("reached_at = ?", s.now().UTC().Truncate(time.Microsecond)).
		Set("failed = ?", "").
		Where("id = ?", id).Exec(ctx)
	if err != nil {
		return fmt.Errorf("record how far that supplier was read: %w", err)
	}
	return nil
}

// ahead is the test that a mark being written is past the one stored.
//
// Written once because the two assignments above have to ask exactly the same
// question: one of them moving without the other leaves a mark that is half of
// one pass and half of another, which orders against neither.
//
// It binds three values, in this order: the moment twice, then the digest. A
// caller passing them in another order is not caught by SQLite, which compares
// a hexadecimal digest against a date as text and answers; the other three
// refuse the statement.
const ahead = `"caught_up_to" IS NULL OR "caught_up_to" < ? ` +
	`OR ("caught_up_to" = ? AND "caught_up_mark" < ?)`

// From is where a source starts reading, as the pair a feed entry is compared
// against, given how far back the deployment reads a supplier's history.
//
// Where it stopped, and never further back than that history before it was
// configured. A publisher's feed lists every advisory they have ever issued —
// tens of thousands for a distribution — so the history is a window rather than
// the whole of it, drained at the per-pass bound. A supplier taken up again
// carries the mark from before it was withdrawn, so it takes what was issued
// while it was away and nothing it already read, within the same window.
func (s Source) From(history time.Duration) (time.Time, string) {
	floor := s.CreatedAt.Add(-history)
	if s.CaughtUpTo != nil && !s.CaughtUpTo.Before(floor) {
		return *s.CaughtUpTo, s.CaughtUpMark
	}
	return floor, ""
}
