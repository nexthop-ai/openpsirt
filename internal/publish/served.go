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
	"github.com/nexthop-ai/openpsirt/internal/advisory"
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

// AnyPublishedForProduct reports whether a document about this product has
// been served to anybody, withdrawn or not: a reader holds it by an address
// and an identifier built from the product's name.
func AnyPublishedForProduct(ctx context.Context, db bun.IDB, productID int64) (bool, error) {
	return anyPublished(ctx, db.NewSelect().Model((*Document)(nil)).
		Where(`"pub"."product_id" = ?`, productID))
}

// AnyPublishedForStream reports whether a document that may name this branch
// or tag has been served, withdrawn or not.
//
// Its own OpenVEX document names it. A CSAF document about an issue in its
// product names each build it states anything about, and which builds a
// revision named is kept in the bytes alone, so once the release has a
// scanned build every CSAF document of its product counts. That refuses a
// rename that might have been safe rather than allowing one that breaks a
// reader's address. A release with no scanned build is in no document.
func AnyPublishedForStream(ctx context.Context, db bun.IDB, streamID int64) (bool, error) {
	return anyPublished(ctx, db.NewSelect().Model((*Document)(nil)).
		Join(`JOIN "stream" AS "st" ON "st"."product_id" = "pub"."product_id"`).
		Where(`"st"."id" = ?`, streamID).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where(`"pub"."kind" = ? AND "pub"."subject" = "st"."name"`, OpenVEX).
				WhereOr(`"pub"."kind" = ? AND EXISTS (?)`, CSAFVEX, scanned(db, "stream_id", "st"))
		}))
}

// AnyPublishedForVariant reports whether a document that may name this
// variant has been served, withdrawn or not: a document of its product, once
// the variant has a scanned build. A variant's name is in every build a
// document names, and which builds those were is in the bytes alone.
func AnyPublishedForVariant(ctx context.Context, db bun.IDB, variantID int64) (bool, error) {
	return anyPublished(ctx, db.NewSelect().Model((*Document)(nil)).
		Join(`JOIN "variant" AS "va" ON "va"."product_id" = "pub"."product_id"`).
		Where(`"va"."id" = ?`, variantID).
		Where("EXISTS (?)", scanned(db, "variant_id", "va")))
}

// scanned asks for a scanned build of the release or variant the outer read
// joins under alias. A build is named by a document only once a scan has
// been filed against it, and the scan it names is never taken away.
func scanned(db bun.IDB, column, alias string) *bun.SelectQuery {
	return db.NewSelect().TableExpr(`"target" AS "tg"`).ColumnExpr("1").
		Where(`"tg".? = ?.?`, bun.Ident(column), bun.Ident(alias), bun.Ident("id")).
		Where(`"tg"."last_scan_id" IS NOT NULL`)
}

// FoldsLike is the displayed name of another product whose documents would be
// published at this product's paths, or empty where there is none.
//
// A CSAF VEX document's filename is built from its product's name under the
// standard's filename rule, so two names that fold alike under it are given
// one path per issue. The other product counts while it publishes, and once
// it has published anything, because a withdrawn document keeps its path.
func FoldsLike(ctx context.Context, db bun.IDB, productID int64, name string) (string, error) {
	var others []struct {
		Name        string `bun:"name"`
		DisplayName string `bun:"display_name"`
	}
	held := db.NewSelect().Model((*Document)(nil)).ColumnExpr("1").
		Where(`"pub"."product_id" = "p"."id"`)
	if err := db.NewSelect().TableExpr(`"product" AS "p"`).
		Column("p.name", "p.display_name").
		Where(`"p"."id" <> ?`, productID).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where(`"p"."publishes" = ?`, true).WhereOr("EXISTS (?)", held)
		}).
		OrderExpr(`"p"."id"`).
		Scan(ctx, &others); err != nil {
		return "", fmt.Errorf("read which products publish: %w", err)
	}
	folded := advisory.Filename(name)
	for _, other := range others {
		if advisory.Filename(other.Name) == folded {
			return other.DisplayName, nil
		}
	}
	return "", nil
}

// anyPublished reports whether the read finds a row.
func anyPublished(ctx context.Context, q *bun.SelectQuery) (bool, error) {
	found, err := q.Limit(1).Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether a document was published: %w", err)
	}
	return found, nil
}

// WithdrawProduct stops every document of a product being served, in the
// transaction that turns the product's publishing off.
//
// Turned on again, a product serves nothing until the next pass has worked
// its documents out again: what it said when it was turned off may since have
// stopped being true. A document stating again what it stated then comes back
// as the revision it was.
func (s *Store) WithdrawProduct(ctx context.Context, productID int64) error {
	if _, err := s.db.NewUpdate().Model((*Document)(nil)).
		Set(`"withdrawn_at" = ?`, s.now().UTC().Truncate(time.Microsecond)).
		Where(`"product_id" = ?`, productID).
		Where(`"withdrawn_at" IS NULL`).
		Exec(ctx); err != nil {
		return fmt.Errorf("withdraw what product %d publishes: %w", productID, err)
	}
	return nil
}
