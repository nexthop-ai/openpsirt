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
// and one that cannot reach out loses this evidence and nothing else.
package supplier

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Source is a supplier this deployment fetches advisories from.
type Source struct {
	bun.BaseModel `bun:"table:advisory_source,alias:as"`

	ID        int64 `bun:"id,pk,autoincrement"`
	ProductID int64 `bun:"product_id,notnull"`
	// Name is what an operator calls this supplier and URL is where the
	// supplier describes what they publish. Two fields rather than one,
	// because a publisher that moves its site is the same supplier and the
	// claims already recorded name them.
	Name string `bun:"name,notnull"`
	URL  string `bun:"url,notnull"`
	// CaughtUpTo is the newest moment in the supplier's feed this source has
	// been read to. Absent until the first pass.
	CaughtUpTo *time.Time `bun:"caught_up_to"`
	// FetchedAt is when a pass last reached this supplier and Failed is what
	// stopped the last one, where something did.
	FetchedAt *time.Time `bun:"fetched_at"`
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

// Due is every supplier still configured that has not been read since before.
//
// Read by the pass, which answers nobody: it carries the deployment's own
// subject because there is no person behind a background cycle, and what it
// asks for is the list it is about to work through.
//
// One never read is due whatever the moment, which is what makes a supplier
// named this morning read this afternoon rather than tomorrow.
func (s *Store) Due(ctx context.Context, subject access.Subject, before time.Time) ([]Source, error) {
	if !subject.Unnarrowed() {
		if err := administering(subject, "read which suppliers are fetched from"); err != nil {
			return nil, err
		}
	}
	var rows []Source
	if err := s.db.NewSelect().Model(&rows).
		Where("retired_at IS NULL").
		Where(`"as"."fetched_at" IS NULL OR "as"."fetched_at" < ?`,
			before.UTC().Truncate(time.Microsecond)).
		// Oldest read first, and one never read before the rest. Nothing
		// bounds how many suppliers a cycle takes, so the order is what keeps
		// one that is slow from being the only one ever reached.
		OrderExpr(`CASE WHEN "as"."fetched_at" IS NULL THEN 0 ELSE 1 END`).
		Order("fetched_at", "id").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which suppliers are fetched from: %w", err)
	}
	return rows, nil
}

// For is every supplier configured against one product.
func (s *Store) For(ctx context.Context, subject access.Subject, productID int64) ([]Source, error) {
	if err := administering(subject, "read which suppliers are fetched from"); err != nil {
		return nil, err
	}
	var rows []Source
	if err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where("retired_at IS NULL").
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
// Taking one up again starts it where a new one starts: at the moment it was
// configured. A source retired for a month and taken up today would otherwise
// fetch the month it was away, which is a burst at a publisher nobody asked
// for and evidence about issues a scan has already reported.
func (s *Store) Add(ctx context.Context, subject access.Subject, productID int64,
	name, address string) (*Source, error) {

	if err := administering(subject, "configure which suppliers are fetched from"); err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	address = strings.TrimSpace(address)
	if name == "" || address == "" {
		return nil, fmt.Errorf("a supplier needs a name and an address")
	}
	if utf8.RuneCountInString(name) > MostName {
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
	now := s.now().UTC().Truncate(time.Microsecond)
	row := &Source{
		ProductID: productID, Name: name, URL: address,
		CreatedBy: subject.ID, CreatedAt: now,
	}
	res, err := s.db.NewUpdate().Model((*Source)(nil)).
		Set("retired_at = ?", nil).
		Set("url = ?", row.URL).
		Set("created_by = ?", row.CreatedBy).
		Set("created_at = ?", row.CreatedAt).
		// Cleared, so the state a fresh source has is the state one taken up
		// again has. A stale mark left behind would be read as a failure by
		// the pass that has not run yet.
		Set("caught_up_to = ?", nil).
		Set("fetched_at = ?", nil).
		Set("failed = ?", "").
		Where("product_id = ?", productID).
		Where("name = ?", name).
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
			Where("product_id = ?", productID).Where("name = ?", name).
			Limit(1).Scan(ctx); err != nil {
			return nil, fmt.Errorf("read that supplier back: %w", err)
		}
		return row, nil
	}
	if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
		return nil, fmt.Errorf("record that supplier: %w", err)
	}
	return row, nil
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
		Where("name = ?", strings.TrimSpace(name)).
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

// Reached records what a pass found, whether or not it found anything.
//
// Written even where nothing came back, because "this supplier has been
// unreachable for a week" is the fact an operator needs and it is only visible
// as a moment that has stopped moving.
//
// caughtUpTo moves forward only. A publisher that revises an old document
// stamps it with the moment of the revision, so a feed entry older than the
// mark is one already taken — and a mark that could go backwards would make a
// supplier who re-stamped one document replay their whole history.
func (s *Store) Reached(ctx context.Context, id int64, caughtUpTo time.Time, failed error) error {
	now := s.now().UTC().Truncate(time.Microsecond)
	because := ""
	if failed != nil {
		because = failed.Error()
	}
	update := s.db.NewUpdate().Model((*Source)(nil)).
		Set("fetched_at = ?", now).
		Set("failed = ?", because).
		Where("id = ?", id)
	if !caughtUpTo.IsZero() {
		update = update.Set("caught_up_to = ?", caughtUpTo.UTC().Truncate(time.Microsecond)).
			Where(`"caught_up_to" IS NULL OR "caught_up_to" < ?`,
				caughtUpTo.UTC().Truncate(time.Microsecond))
	}
	if _, err := update.Exec(ctx); err != nil {
		return fmt.Errorf("record what came back from that supplier: %w", err)
	}
	return nil
}

// From is where a source starts reading when nothing has been read yet.
//
// The moment it was configured, rather than the beginning of the publisher's
// history. A publisher's feed lists every advisory they have ever issued —
// tens of thousands for a distribution — and taking them is a burst at somebody
// else's service that would drain over months and arrive as evidence about
// issues a scan reported long ago. What a deployment wants from history is one
// document at a time, which the upload path already takes.
func (s Source) From() time.Time {
	if s.CaughtUpTo != nil {
		return *s.CaughtUpTo
	}
	return s.CreatedAt
}
