// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package upstream reads the VEX documents an upstream publishes, for a product
// that forks it (REQ-84).
//
// An administrator names the upstream's provider description against one
// product and confirms the key its documents are signed with. A pass reads
// what the upstream lists from then on, checks every document against the
// digest and the signature served beside it, and records what each says as a
// third party's statements. A statement the upstream publishes as holding for
// anybody shipping the component is applied by the run, at that component and
// version; one that depends on the upstream's own build is offered for review.
// Neither is ever wider than what it says (REQ-31).
//
// Every request goes to the host an administrator named, and nowhere else.
package upstream

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Upstream is the provider a product trusts the published statements of.
type Upstream struct {
	bun.BaseModel `bun:"table:upstream,alias:up"`

	ID        int64  `bun:"id,pk,autoincrement"`
	ProductID int64  `bun:"product_id,notnull"`
	URL       string `bun:"url,notnull"`
	// Publisher is whose statements they are, as the provider description
	// named its publisher when the upstream was trusted.
	Publisher string `bun:"publisher,notnull"`
	// Fingerprint and PublicKey are the key the documents are signed with,
	// as an administrator confirmed it. Both empty where the upstream signs
	// nothing.
	Fingerprint string `bun:"fingerprint,nullzero"`
	PublicKey   string `bun:"public_key,nullzero"`
	// KeyOffered is a key the upstream names that is not the one trusted.
	// Nothing is read while it is set.
	KeyOffered string `bun:"key_offered,nullzero"`
	// Listings is what each listing last answered with, as a validator a
	// request repeats.
	Listings  string     `bun:"listings,nullzero"`
	FetchedAt *time.Time `bun:"fetched_at"`
	ReachedAt *time.Time `bun:"reached_at"`
	Failed    string     `bun:"failed,nullzero"`
	TrustedBy int64      `bun:"trusted_by,notnull"`
	TrustedAt time.Time  `bun:"trusted_at,notnull"`
}

// Document is one document an upstream lists, at the revision last recorded.
type Document struct {
	bun.BaseModel `bun:"table:upstream_document,alias:ud"`

	ID         int64     `bun:"id,pk,autoincrement"`
	UpstreamID int64     `bun:"upstream_id,notnull"`
	URL        string    `bun:"url,notnull"`
	URLDigest  string    `bun:"url_digest,notnull"`
	TrackingID string    `bun:"tracking_id,notnull"`
	ListedAt   string    `bun:"listed_at,notnull"`
	Digest     string    `bun:"digest,notnull"`
	RecordedAt time.Time `bun:"recorded_at,notnull"`
}

// MostURL bounds the address an upstream is named by and the address of each
// document, which every statement it leaves records.
const MostURL = 1000

// MostReason bounds what is kept of why an upstream could not be read. The
// text carries the upstream's own address and a server's own reason phrase.
const MostReason = 400

// Store reads and writes the upstreams products trust.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// ErrUnusable says an address cannot name an upstream.
var ErrUnusable = refusal.New("an upstream is named by an https address with a host and no user")

// Address checks an address an administrator typed and answers it parsed.
func Address(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MostURL {
		return nil, fmt.Errorf("%w, of at most %d characters", ErrUnusable, MostURL)
	}
	at, err := url.Parse(raw)
	if err != nil || at.Scheme != "https" || at.Host == "" || at.User != nil ||
		at.Opaque != "" {
		return nil, ErrUnusable
	}
	return at, nil
}

// For is the upstream a product trusts, or nil where it trusts none.
func (s *Store) For(ctx context.Context, subject access.Subject, productID int64) (*Upstream, error) {
	if err := subject.Administering("read which upstream a product trusts"); err != nil {
		return nil, err
	}
	return s.of(ctx, s.db, productID)
}

func (s *Store) of(ctx context.Context, db bun.IDB, productID int64) (*Upstream, error) {
	up := new(Upstream)
	err := db.NewSelect().Model(up).Where(`"up"."product_id" = ?`, productID).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read which upstream a product trusts: %w", err)
	}
	return up, nil
}

// Trusting is what an administrator confirms in trusting an upstream: where it
// is, whose statements they are, and the key its documents are signed with.
type Trusting struct {
	URL         string
	Publisher   string
	Fingerprint string
	PublicKey   string
}

// Trust records that a product trusts an upstream, trusts its key again, or
// reads it at another address.
//
// The same address again trusts the key given and clears a key offered in
// place of the one trusted. Another address is the same upstream moved: what
// it said stands, the key trusted stays the one documents are checked
// against, and a key the new address names that differs is recorded as
// offered, so nothing is read until it is trusted. What the upstream said is
// reconciled against the new address by its first complete read.
func (s *Store) Trust(ctx context.Context, subject access.Subject, productID int64,
	trusting Trusting) (*Upstream, error) {

	if err := subject.Administering("trust an upstream"); err != nil {
		return nil, err
	}
	if _, err := Address(trusting.URL); err != nil {
		return nil, err
	}
	trusting.Publisher = bound.Text(strings.TrimSpace(trusting.Publisher))
	if trusting.Publisher == "" || len([]rune(trusting.Publisher)) > finding.MostPublisher {
		return nil, refusal.Errorf("an upstream's provider description names its publisher in "+
			"at most %d characters, and this one does not", finding.MostPublisher)
	}
	var out *Upstream
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		out = nil
		now := s.now().Truncate(time.Microsecond)
		held, err := s.of(ctx, tx, productID)
		if err != nil {
			return err
		}
		switch {
		case held == nil:
			out = &Upstream{
				ProductID: productID, URL: trusting.URL, Publisher: trusting.Publisher,
				Fingerprint: trusting.Fingerprint, PublicKey: trusting.PublicKey,
				TrustedBy: subject.ID, TrustedAt: now,
			}
			if _, err := tx.NewInsert().Model(out).Exec(ctx); err != nil {
				return fmt.Errorf("trust an upstream: %w", err)
			}
			return nil
		case held.URL == trusting.URL:
			held.Fingerprint, held.PublicKey, held.KeyOffered = trusting.Fingerprint, trusting.PublicKey, ""
		default:
			held.URL, held.Listings, held.FetchedAt = trusting.URL, "", nil
			held.KeyOffered = ""
			if trusting.Fingerprint != held.Fingerprint {
				held.KeyOffered = trusting.Fingerprint
				if held.KeyOffered == "" {
					held.KeyOffered = NoKey
				}
			}
		}
		// What stopped the last read stays until a read succeeds: trusting
		// again is not a read, and an upstream said to be failing is said to
		// be read again only once it is.
		held.TrustedBy, held.TrustedAt = subject.ID, now
		if _, err := tx.NewUpdate().Model(held).
			Column("url", "listings", "fetched_at", "fingerprint", "public_key", "key_offered",
				"trusted_by", "trusted_at").
			WherePK().Exec(ctx); err != nil {
			return fmt.Errorf("trust an upstream again: %w", err)
		}
		out = held
		return nil
	})
	return out, err
}

// NoKey is the key an upstream offers where it names none, recorded where a
// key was trusted.
const NoKey = "none"

// Withdraw stops a product trusting its upstream, answering the upstream it
// trusted, or nil where it trusted none.
//
// Everything the upstream said is set aside, so the next run opens what its
// statements closed and nothing it said is offered. The statements stay
// readable, because a decision somebody made citing one has to stay
// explicable.
func (s *Store) Withdraw(ctx context.Context, subject access.Subject, productID int64) (*Upstream, error) {
	if err := subject.Administering("stop trusting an upstream"); err != nil {
		return nil, err
	}
	var out *Upstream
	err := database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		out = nil
		held, err := s.of(ctx, tx, productID)
		if err != nil || held == nil {
			return err
		}
		if err := s.forget(ctx, tx, held, s.now().Truncate(time.Microsecond)); err != nil {
			return err
		}
		out = held
		return nil
	})
	return out, err
}

// forget removes an upstream and what has been read of it, and sets aside
// every statement it made.
func (s *Store) forget(ctx context.Context, tx bun.IDB, held *Upstream, now time.Time) error {
	if _, err := tx.NewUpdate().Model((*finding.Statement)(nil)).
		Set(`"superseded_at" = ?`, now).
		Where(`"product_id" = ?`, held.ProductID).
		Where(`"source" = ?`, finding.FromUpstream).
		Where(`"superseded_at" IS NULL`).
		Exec(ctx); err != nil {
		return fmt.Errorf("set aside what an upstream said: %w", err)
	}
	if _, err := tx.NewDelete().Model((*Document)(nil)).
		Where(`"upstream_id" = ?`, held.ID).Exec(ctx); err != nil {
		return fmt.Errorf("forget what was read of an upstream: %w", err)
	}
	if _, err := tx.NewDelete().Model((*Upstream)(nil)).
		Where(`"id" = ?`, held.ID).Exec(ctx); err != nil {
		return fmt.Errorf("stop trusting an upstream: %w", err)
	}
	return nil
}

// Due is every upstream of a product in use that no pass has tried since
// before.
//
// Read by the pass, which answers nobody, so it is asked of the deployment
// itself.
func (s *Store) Due(ctx context.Context, subject access.Subject, before time.Time) ([]Upstream, error) {
	if !subject.Unnarrowed() {
		return nil, access.Denied("list the upstreams due a read")
	}
	var out []Upstream
	err := s.db.NewSelect().Model(&out).
		Join(`JOIN "product" AS "pr" ON "pr"."id" = "up"."product_id"`).
		Where(`"pr"."retired_at" IS NULL`).
		Where(`"up"."fetched_at" IS NULL OR "up"."fetched_at" < ?`, before).
		OrderExpr(`"up"."id"`).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read which upstreams are due a read: %w", err)
	}
	return out, nil
}

// standing reads an upstream again inside a transaction, answering nil where it
// is no longer trusted as it was when a pass began.
func standing(ctx context.Context, tx bun.IDB, held Upstream) (*Upstream, error) {
	up := new(Upstream)
	err := tx.NewSelect().Model(up).Where(`"up"."id" = ?`, held.ID).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read whether an upstream is still trusted: %w", err)
	}
	if up.Fingerprint != held.Fingerprint || up.URL != held.URL {
		return nil, nil
	}
	return up, nil
}

// reached records how a pass over an upstream went: when it was tried, when
// it last worked, what stopped it, what each listing answered with, and a key
// offered in place of the trusted one. A pass that stopped at its bound
// leaves the upstream due, so the rest is read on the next wake rather than
// after the interval.
//
// Written only while the upstream is trusted at the address the pass read: a
// pass still running against an address an administrator just moved from
// leaves what the move set alone.
func (s *Store) reached(ctx context.Context, held Upstream, listings, offered string, failed error,
	due bool) error {
	now := s.now().Truncate(time.Microsecond)
	q := s.db.NewUpdate().Model((*Upstream)(nil)).
		Set(`"listings" = ?`, nullable(listings)).
		Set(`"key_offered" = ?`, nullable(offered)).
		Where(`"id" = ?`, held.ID).
		Where(`"url" = ?`, held.URL)
	if !due {
		q = q.Set(`"fetched_at" = ?`, now)
	}
	if failed != nil {
		q = q.Set(`"failed" = ?`, bound.HeadRunes(bound.Text(failed.Error()), MostReason))
	} else {
		q = q.Set(`"failed" = NULL`).Set(`"reached_at" = ?`, now)
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("record how an upstream was read: %w", err)
	}
	return nil
}

// nullable is a value, or null where it is empty.
func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// digestOf is the digest an address is matched on.
func digestOf(address string) string {
	sum := sha256.Sum256([]byte(address))
	return hex.EncodeToString(sum[:])
}
