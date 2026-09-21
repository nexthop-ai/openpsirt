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
	// Every product it covers is one this reader holds something on. Without
	// it the clause below asks only whether a visibility is one they may read
	// somewhere, so a public flaw in a product they hold nothing on passes —
	// and the row carries the identifier, the title, the summary and the
	// digest.
	q = q.Where(`NOT EXISTS (SELECT 1 FROM "advisory_issue" AS "ap"
		WHERE ap.advisory_id = ad.id AND ap.removed_at IS NULL
		  AND ap.product_id NOT IN (?))`, bun.List(seen(subject)))

	// And every issue it covers is one they may see. Asked of the issues
	// rather than of the issuance, because that is where a visibility lives —
	// an issuance carries none of its own, and reading one as public because
	// it has no visibility column is how an undisclosed flaw would be
	// announced by the report about announcements.
	//
	// Whole rather than in part, for the reason the document is: a row saying
	// an advisory went out, about a product this reader holds nothing on, is
	// the disclosure the narrowing exists to stop.
	return q.Where(`NOT EXISTS (SELECT 1 FROM "advisory_issue" AS "ac"
		WHERE ac.advisory_id = ad.id AND ac.removed_at IS NULL AND NOT EXISTS (
			SELECT 1 FROM "finding" AS "f"
			JOIN "target" AS "t" ON t.id = f.target_id
			JOIN "stream" AS "st" ON st.id = t.stream_id
			WHERE st.product_id = ac.product_id
			  AND f.vulnerability_id = ac.vulnerability_id
			  AND f.kind = ?
			  AND f.visibility IN (?)))`,
		finding.Entered, bun.List(readable(subject)))
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
		// By name and then newest first, so that what is written is decided
		// by the record rather than by the order an engine chose.
		OrderExpr("ad.identifier ASC, ai.ordinal DESC")

	var rows []Sent
	if err := narrowed(q, subject).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the documents that went out: %w", err)
	}
	return rows, nil
}

// readable is the visibilities this subject may read anywhere.
//
// A statement spanning products cannot bind one product's answer, so what it
// binds is the union: public always, and private where this subject reads it
// on any product. On its own it is too loose — a public flaw in a product
// they hold nothing on reads as visible — so the clause above it asks the
// product half, and neither stands without the other.
func readable(subject access.Subject) []access.Visibility {
	products, all := subject.Products()
	if all {
		return []access.Visibility{access.Public, access.Private}
	}
	for _, id := range products {
		if subject.Reads(access.Private, id) {
			return []access.Visibility{access.Public, access.Private}
		}
	}
	return []access.Visibility{access.Public}
}
