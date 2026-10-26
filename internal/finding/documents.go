// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Document is one third-party document a product holds statements from, as the
// statements it made describe it.
//
// No upload of one is stored apart from its statements, so this is worked out
// from them: a document is the key a later upload replaces on — the kind, the
// publisher and the name the publisher gave it — and what stands under that
// key.
type Document struct {
	Source     string `bun:"source"`
	Publisher  string `bun:"publisher"`
	Identifier string `bun:"document_id"`
	// Name is the file the document last arrived as, or the address a feed
	// fetched it from. Digest is what that copy hashed to. Both are of the
	// statements still standing where any are.
	Name   string `bun:"document"`
	Digest string `bun:"digest"`
	// Standing is how many of its statements stand and SetAside how many a
	// later copy of it no longer made.
	Standing int `bun:"standing"`
	SetAside int `bun:"set_aside"`
	// FirstAt is when the first statement under its key was recorded, and
	// ChangedAt the last time an upload wrote anything under it: a statement
	// recorded, said again, or set aside. The same bytes uploaded again write
	// nothing, so they move neither.
	FirstAt   time.Time `bun:"first_at"`
	ChangedAt time.Time `bun:"changed_at"`
}

// Fetched reports whether a supplier advisory feed fetched the document rather
// than somebody uploading it. A fetched document is recorded under the address
// it came from, and an uploaded one under a file name, which never holds a
// slash.
func (d Document) Fetched() bool { return strings.Contains(d.Name, "/") }

// Documents is the documents of one kind a product holds statements from, the
// most recently changed first, with how many there are.
//
// Read by a person who may know the product exists, which is who reads the
// product's uploads. A pipeline key sends inventories rather than these, and
// reads nothing about them.
func (s *Store) Documents(ctx context.Context, subject access.Subject, productID int64,
	source string, limit, offset int) ([]Document, int, error) {

	if !subject.Unnarrowed() && (subject.Kind != access.Person || !subject.Sees(productID)) {
		return nil, 0, access.Denied(fmt.Sprintf("read the documents uploaded to product %d", productID))
	}
	limit = database.AList.Of(limit)
	of := func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.TableExpr(`"vex_statement" AS "ss"`).
			Where(`"ss"."product_id" = ?`, productID).
			Where(`"ss"."source" = ?`, source).
			GroupExpr(`"ss"."source", "ss"."publisher", "ss"."document_id"`)
	}

	total, err := s.db.NewSelect().
		TableExpr(`(?) AS "held"`, of(s.db.NewSelect()).ColumnExpr(`"ss"."publisher"`)).
		Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count the documents held: %w", err)
	}

	var held []Document
	err = of(s.db.NewSelect()).
		ColumnExpr(`"ss"."source" AS "source"`).
		ColumnExpr(`"ss"."publisher" AS "publisher"`).
		ColumnExpr(`"ss"."document_id" AS "document_id"`).
		// Every standing statement of a document carries the copy it last
		// arrived as, because a statement said again is moved onto it. Where
		// none stands, any copy it arrived as names it.
		ColumnExpr(`COALESCE(MAX(CASE WHEN "ss"."superseded_at" IS NULL THEN "ss"."document" END), `+
			`MAX("ss"."document")) AS "document"`).
		ColumnExpr(`COALESCE(MAX(CASE WHEN "ss"."superseded_at" IS NULL THEN "ss"."digest" END), `+
			`MAX("ss"."digest")) AS "digest"`).
		ColumnExpr(`SUM(CASE WHEN "ss"."superseded_at" IS NULL THEN 1 ELSE 0 END) AS "standing"`).
		ColumnExpr(`SUM(CASE WHEN "ss"."superseded_at" IS NULL THEN 0 ELSE 1 END) AS "set_aside"`).
		ColumnExpr(`MIN("ss"."uploaded_at") AS "first_at"`).
		// A row is written when it is recorded, said again and set aside, in
		// that order, and set aside ends it.
		ColumnExpr(`MAX(COALESCE("ss"."superseded_at", "ss"."restated_at", "ss"."uploaded_at")) AS "changed_at"`).
		OrderExpr(`MAX(COALESCE("ss"."superseded_at", "ss"."restated_at", "ss"."uploaded_at")) DESC`).
		OrderExpr(`"ss"."publisher" ASC, "ss"."document_id" ASC`).
		Limit(int64(limit)).Offset(int64(offset)).
		Scan(ctx, &held)
	if err != nil {
		return nil, 0, fmt.Errorf("read the documents held: %w", err)
	}
	for i := range held {
		held[i].FirstAt, held[i].ChangedAt = held[i].FirstAt.UTC(), held[i].ChangedAt.UTC()
	}
	return held, int(total), nil
}
