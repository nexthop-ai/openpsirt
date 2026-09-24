// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Went is one advisory that went out, as a report about a period reads it.
type Went struct {
	// Advisory is the name it went out under, and Title what it was called.
	Advisory string
	Title    string
	// Issues is how many it covered and Products how many products those sat
	// in. The two together, because one issue in three products and three
	// issues in one are different documents.
	Issues   int
	Products int
	// Ordinal is which issuance this was, counting from one. More than one
	// means the advisory was revised, which is the thing a coordinator is
	// looking for in a list like this.
	Ordinal  int
	Summary  string
	IssuedBy string
	IssuedAt time.Time
	Digest   string
}

// Published is what has gone out, newest first, across every flaw a reader may
// see.
//
// Answered per flaw until now, which is the right shape for somebody
// deciding whether to publish a revision and the wrong one for the question a
// period asks: what went out, and what went out twice.
//
// Narrowed the way every other read here is. An advisory is about a flaw
// recorded by hand in this deployment, and one of those may be undisclosed —
// so the row is shown only where the reader may see the finding it was written
// about, and a count is as much a disclosure as a row.
func (s *Store) Published(ctx context.Context, subject access.Subject,
	productIDs []int64, since, until time.Time) ([]Went, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read what advisories have gone out")
	}
	if products, all := subject.Products(); !all && len(products) == 0 {
		return nil, nil
	}

	q := s.db.NewSelect().
		TableExpr(`"advisory_issuance" AS "ai"`).
		Join(`JOIN "advisory" AS "ad" ON ad.id = ai.advisory_id`).
		Join(`JOIN "person" AS "pe" ON pe.id = ai.issued_by`).
		// The title the document carried when it went out, not the one the
		// advisory has now. A record of what was published says what was
		// published.
		Join(`JOIN "advisory_edition" AS "ae" ON ae.id = ai.edition_id`).
		ColumnExpr(`ad.identifier AS "advisory"`).
		ColumnExpr(`COALESCE(ae.title, '') AS "title"`).
		ColumnExpr(`ai.ordinal AS "ordinal"`).
		ColumnExpr(`ai.summary AS "summary"`).
		ColumnExpr(`pe.identity AS "issued_by"`).
		ColumnExpr(`ai.issued_at AS "issued_at"`).
		ColumnExpr(`ai.digest AS "digest"`).
		ColumnExpr(`(SELECT COUNT(*) FROM "advisory_issue" AS "ai2"
			WHERE ai2.advisory_id = ad.id AND ai2.removed_at IS NULL) AS "issues"`).
		ColumnExpr(`(SELECT COUNT(DISTINCT ai3.product_id) FROM "advisory_issue" AS "ai3"
			WHERE ai3.advisory_id = ad.id AND ai3.removed_at IS NULL) AS "products"`).
		OrderExpr("ai.issued_at DESC, ai.id DESC")
	if len(productIDs) > 0 {
		q = q.Where(`EXISTS (SELECT 1 FROM "advisory_issue" AS "ai4"
			WHERE ai4.advisory_id = ad.id AND ai4.removed_at IS NULL
			  AND ai4.product_id IN (?))`, bun.List(productIDs))
	}
	// Either side, or neither: an unbounded side is the beginning or now,
	// which is what a period's zero side means everywhere else here.
	if !since.IsZero() {
		q = q.Where("ai.issued_at >= ?", since)
	}
	if !until.IsZero() {
		q = q.Where("ai.issued_at < ?", until)
	}

	var rows []Went
	if err := narrowed(q, subject).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what has been published: %w", err)
	}
	return rows, nil
}

// narrowed is what a reader of issuances may see, as the clauses a statement
// over "advisory_issuance" joined to "advisory" adds.
//
// One spelling for every such statement. Two of them ask this and they are
// the same question — what has gone out, and what may be served from what
// went out — so spelled twice they would disagree, and the one that disagreed
// would hand out a document about a product somebody holds nothing on.
//
// It takes the alias the advisory carries in both: "ad".
func narrowed(q *bun.SelectQuery, subject access.Subject) *bun.SelectQuery {
	// The product half is inside it: a product this reader holds nothing on
	// is in none of the groups the issue clause admits.
	return wholeIssues(q, subject)
}

// wholeIssues narrows a statement over "advisory" as "ad" to the advisories
// every live issue of which this reader may see: a finding recorded here about
// it, in its product, at a visibility they read in that product.
//
// Asked of the issues rather than of an issuance, because that is where a
// visibility lives — an issuance carries none of its own, and reading one as
// public because it has no visibility column is how an undisclosed flaw would
// be announced by the report about announcements.
//
// Per product and per visibility. Each visibility is its own grant, so a
// reader of undisclosed work in one product and disclosed work in another
// reads neither kind in both. Whole rather than in part, for the reason the
// document is: a row saying an advisory went out is as much a disclosure as
// the document.
func wholeIssues(q *bun.SelectQuery, subject access.Subject) *bun.SelectQuery {
	products, all := subject.Products()
	if all {
		return q
	}
	both, public, private := access.Split(products, subject.Reads)
	where, args := access.VisibleWhere("st.product_id", "f.visibility", both, public, private)
	return q.Where(`NOT EXISTS (SELECT 1 FROM "advisory_issue" AS "ac"
		WHERE ac.advisory_id = ad.id AND ac.removed_at IS NULL AND NOT EXISTS (
			SELECT 1 FROM "finding" AS "f"
			JOIN "target" AS "t" ON t.id = f.target_id
			JOIN "stream" AS "st" ON st.id = t.stream_id
			WHERE st.product_id = ac.product_id
			  AND f.vulnerability_id = ac.vulnerability_id
			  AND f.kind = ?
			  AND `+where+`))`,
		append([]any{finding.Entered}, args...)...)
}

// Sent is one document that went out, as what publishes it reads it.
//
// The bytes rather than the advisory they were generated from. What a
// directory serves is what was published, and the record it came from has
// moved on.
type Sent struct {
	// Advisory is the name it went out under and Ordinal which issuance this
	// was, counting from one. The pair is what a log line names, because a
	// file is written from one of them and the identifier alone does not say
	// which.
	Advisory string `bun:"advisory"`
	Ordinal  int    `bun:"ordinal"`
	Document string `bun:"document"`
}

// Everything that has gone out, newest issuance first within each advisory.
//
// Every issuance rather than the newest of each, because whether one may be
// served is a property of the bytes: a document about a flaw nobody outside
// has been told about travels no further, and the newest revision of an
// advisory can be one of those while the revision before it is already
// public. What publishes walks each advisory until it reaches one it may
// serve.
//
// An issuance v0.1.0 recorded kept no document, so there is nothing of it to
// serve and it is not among them.
//
// Narrowed the way every other read of an issuance is, which for the
// deployment looking at itself narrows to everything.
func (s *Store) Sent(ctx context.Context, subject access.Subject) ([]Sent, error) {
	if subject.Kind != access.Person {
		return nil, access.Denied("read what advisories have gone out")
	}
	if products, all := subject.Products(); !all && len(products) == 0 {
		return nil, nil
	}
	q := s.db.NewSelect().
		TableExpr(`"advisory_issuance" AS "ai"`).
		Join(`JOIN "advisory" AS "ad" ON ad.id = ai.advisory_id`).
		ColumnExpr(`ad.identifier AS "advisory"`).
		ColumnExpr(`ai.ordinal AS "ordinal"`).
		ColumnExpr(`ai.document AS "document"`).
		Where("ai.document IS NOT NULL").
		// By name and then newest first, so that what is written is decided
		// by the record rather than by the order an engine chose.
		OrderExpr("ad.identifier ASC, ai.ordinal DESC")

	var rows []Sent
	if err := narrowed(q, subject).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the documents that went out: %w", err)
	}
	return rows, nil
}

// AnyIssuedForProduct reports whether an advisory covering one product has
// gone out.
//
// What a product rename is refused on. A published advisory names each
// affected release in its product tree by the build it is — the product, the
// release and the variant — and that identifier is what a customer's tooling
// matches itself against. Renamed afterwards, the next revision names the same
// release differently, and a reader matching the identifier they hold finds it
// absent: which reads as no longer affected, about a customer who still is.
//
// The issue an advisory covers is recorded against the product, so this is
// exact rather than inferred. An issue added since the last issuance is named
// in no document yet, for the reason its counterpart over a release gives.
func AnyIssuedForProduct(ctx context.Context, db bun.IDB, productID int64) (bool, error) {
	issued, err := db.NewSelect().Model((*Issuance)(nil)).
		Join(`JOIN "advisory_issue" AS "ac" ON ac.advisory_id = ai.advisory_id`).
		Where("ac.product_id = ?", productID).
		Where("ac.added_at <= ai.issued_at").
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether an advisory has gone out for this product: %w", err)
	}
	return issued, nil
}

// AnyIssuedForStream reports whether a published advisory named one release.
//
// A release reaches the product tree by holding one of the issues the advisory
// covers, so that is what is asked. Asked of the product instead, a release
// that no advisory ever named would be refused a correction because a sibling
// release was named once — and a release cannot be retired and declared again
// as a way round it, because the second one would hold none of its history.
//
// An issue taken back off the advisory still counts, and one added after the
// last issuance does not. What went out is what readers hold: a document is
// not rewritten, so an issue removed since is still named in it and an issue
// added since is named in no document yet.
//
// The issue is covered in one product, and a release belongs to one product,
// so the two have to be the same product. Left unjoined, one upstream flaw
// shared between two products made an advisory for either refuse a rename on
// the other, which is the over-refusal asking about the release rather than
// about the product exists to avoid.
func AnyIssuedForStream(ctx context.Context, db bun.IDB, streamID int64) (bool, error) {
	issued, err := db.NewSelect().Model((*Issuance)(nil)).
		Join(`JOIN "advisory_issue" AS "ac" ON ac.advisory_id = ai.advisory_id`).
		Join(`JOIN "finding" AS "f" ON f.vulnerability_id = ac.vulnerability_id`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Where("tg.stream_id = ?", streamID).
		Where(`"st"."product_id" = "ac"."product_id"`).
		Where("ac.added_at <= ai.issued_at").
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether an advisory has gone out for this release: %w", err)
	}
	return issued, nil
}
