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
		ColumnExpr(`ad.identifier AS "advisory"`).
		ColumnExpr(`COALESCE(ad.title, '') AS "title"`).
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
			  AND ai4.product_id IN (?))`, bun.In(productIDs))
	}
	// Either side, or neither: an unbounded side is the beginning or now,
	// which is what a period's zero side means everywhere else here.
	if !since.IsZero() {
		q = q.Where("ai.issued_at >= ?", since)
	}
	if !until.IsZero() {
		q = q.Where("ai.issued_at < ?", until)
	}

	// The advisory has to be one this reader may see the whole of, which is
	// the rule reading one by name applies. Asked of the issues it covers
	// rather than of the issuance, because that is where a visibility lives —
	// an issuance carries none of its own, and reading one as public because
	// it has no visibility column is how an undisclosed flaw would be
	// announced by the report about announcements.
	//
	// Whole rather than in part, for the reason the document is: a row saying
	// an advisory went out, about a product this reader holds nothing on, is
	// the disclosure the narrowing exists to stop.
	q = q.Where(`NOT EXISTS (SELECT 1 FROM "advisory_issue" AS "ac"
		WHERE ac.advisory_id = ad.id AND ac.removed_at IS NULL AND NOT EXISTS (
			SELECT 1 FROM "finding" AS "f"
			JOIN "target" AS "t" ON t.id = f.target_id
			JOIN "stream" AS "st" ON st.id = t.stream_id
			WHERE st.product_id = ac.product_id
			  AND f.vulnerability_id = ac.vulnerability_id
			  AND f.kind = ?
			  AND f.visibility IN (?)))`,
		finding.Entered, bun.In(readable(subject)))

	var rows []Went
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what has been published: %w", err)
	}
	return rows, nil
}

// readable is the visibilities this subject may read anywhere.
//
// A statement spanning products cannot bind one product's answer, so what it
// binds is the union: public always, and private where this subject reads it
// on any product. The product half of the rule is asked separately, by the
// clause that requires every issue to sit in a product they hold.
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
