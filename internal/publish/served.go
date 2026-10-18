// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Store reads and writes the published documents.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// ErrNotPublished is a path that names no document the reader may be handed.
//
// One answer for a path nothing was ever written at, a document about a
// product that does not publish, a document withdrawn, and one written under
// wider statuses than the deployment publishes now. Telling them apart would
// tell anybody at all which products and issues exist.
var ErrNotPublished = errors.New("no document is published there")

// Listing is one published document as a list names it, without its bytes.
type Listing struct {
	Kind       string    `bun:"kind"`
	Path       string    `bun:"path"`
	TrackingID string    `bun:"tracking_id"`
	Title      string    `bun:"title"`
	Version    int       `bun:"version"`
	FirstAt    time.Time `bun:"first_at"`
	CurrentAt  time.Time `bun:"current_at"`
}

// Listed is every document the subject may be handed, as the lists name them,
// under the statuses the deployment publishes now.
//
// Ordered by path, so two answers over the same documents are the same.
func (s *Store) Listed(ctx context.Context, subject access.Subject,
	statuses string) ([]Listing, error) {

	q := s.db.NewSelect().Model((*Document)(nil)).
		Column("kind", "path", "tracking_id", "title", "version", "first_at", "current_at").
		OrderExpr(`"pub"."path"`)
	q, ok, err := served(q, subject, statuses)
	if err != nil || !ok {
		return nil, err
	}
	var out []Listing
	if err := q.Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("read the published documents: %w", err)
	}
	for i := range out {
		out[i].FirstAt, out[i].CurrentAt = out[i].FirstAt.UTC(), out[i].CurrentAt.UTC()
	}
	return out, nil
}

// At is the document served at path, or ErrNotPublished.
func (s *Store) At(ctx context.Context, subject access.Subject, path,
	statuses string) (*Document, error) {

	doc := new(Document)
	q, ok, err := served(s.db.NewSelect().Model(doc).
		Where(`"pub"."path_digest" = ?`, digestOf(path)), subject, statuses)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotPublished
	}
	switch err := q.Scan(ctx); {
	case database.IsNoRows(err):
		return nil, ErrNotPublished
	case err != nil:
		return nil, fmt.Errorf("read a published document: %w", err)
	}
	// The digest is of the path, so a collision would hand over a document
	// served somewhere else. Compared whole rather than trusted.
	if doc.Path != path {
		return nil, ErrNotPublished
	}
	doc.FirstAt, doc.CurrentAt = doc.FirstAt.UTC(), doc.CurrentAt.UTC()
	return doc, nil
}

// served narrows a read of the published documents to what the subject may be
// handed: documents about a product whose disclosed work it reads, not
// withdrawn, and written under statuses no wider than the deployment publishes
// now. It answers false where nothing can be, so the read is not made.
//
// Anybody at all and the deployment itself may ask, and nobody else. A
// signed-in person reads findings through the API, which is where their
// grants are answered; a reader of what is published reads only what anybody
// may.
func served(q *bun.SelectQuery, subject access.Subject, statuses string) (*bun.SelectQuery, bool, error) {
	if subject.Kind != access.Anonymous && !subject.Unnarrowed() {
		return nil, false, access.Denied("read the published documents")
	}
	q = q.Where(`"pub"."withdrawn_at" IS NULL`)
	if statuses == setting.SettledStatuses {
		q = q.Where(`"pub"."statuses" = ?`, setting.SettledStatuses)
	}
	products, all := subject.Products()
	if all {
		return q, true, nil
	}
	var readable []int64
	for _, id := range products {
		if subject.Reads(access.Public, id) {
			readable = append(readable, id)
		}
	}
	if len(readable) == 0 {
		return nil, false, nil
	}
	return q.Where(`"pub"."product_id" IN (?)`, bun.List(readable)), true, nil
}
