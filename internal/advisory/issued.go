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
	Product string
	Issue   string
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
// **Answered per flaw until now**, which is the right shape for somebody
// deciding whether to publish a revision and the wrong one for the question a
// period asks: what went out, and what went out twice.
//
// Narrowed the way every other read here is. An advisory is about a flaw
// recorded by hand in this deployment, and one of those may be undisclosed —
// so the row is shown only where the reader may see the finding it was written
// about, and a count is as much a disclosure as a row.
func (s *Store) Published(ctx context.Context, subject access.Subject,
	productIDs []int64, since time.Time) ([]Went, error) {

	products, all := subject.Products()
	if subject.Kind != access.Person || (!all && len(products) == 0) {
		return nil, nil
	}

	q := s.db.NewSelect().
		TableExpr("advisory_issuance AS ai").
		Join(`JOIN "product" AS pd ON pd.id = ai.product_id`).
		Join(`JOIN "vulnerability" AS v ON v.id = ai.vulnerability_id`).
		Join(`JOIN "person" AS pe ON pe.id = ai.issued_by`).
		ColumnExpr("pd.name AS product").
		ColumnExpr("v.identifier AS issue").
		ColumnExpr("ai.ordinal AS ordinal").
		ColumnExpr("ai.summary AS summary").
		ColumnExpr("pe.identity AS issued_by").
		ColumnExpr("ai.issued_at AS issued_at").
		ColumnExpr("ai.digest AS digest").
		OrderExpr("ai.issued_at DESC, ai.id DESC")
	if !all {
		q = q.Where("ai.product_id IN (?)", bun.List(products))
	}
	if len(productIDs) > 0 {
		q = q.Where("ai.product_id IN (?)", bun.List(productIDs))
	}
	if !since.IsZero() {
		q = q.Where("ai.issued_at >= ?", since)
	}

	// The flaw it was written about has to be one this reader may see. Asked
	// of the recorded finding rather than of the issuance, because that is
	// where a visibility lives — an issuance carries none of its own, and
	// reading one as public because it has no visibility column is how an
	// undisclosed flaw would be announced by the report about announcements.
	visible := `EXISTS (SELECT 1 FROM "finding" AS f
		JOIN "target" AS t ON t.id = f.target_id
		JOIN "stream" AS st ON st.id = t.stream_id
		WHERE st.product_id = ai.product_id
		  AND f.vulnerability_id = ai.vulnerability_id
		  AND f.kind = ?`
	args := []any{finding.Entered}
	if all {
		visible += ")"
	} else {
		held := make([]int64, 0, len(products))
		for _, id := range products {
			if subject.Reads(access.Private, id) {
				held = append(held, id)
			}
		}
		if len(held) == 0 {
			visible += " AND f.visibility = ?)"
			args = append(args, access.Public)
		} else {
			visible += " AND (f.visibility = ? OR st.product_id IN (?)))"
			args = append(args, access.Public, bun.List(held))
		}
	}
	q = q.Where(visible, args...)

	var rows []Went
	if err := q.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what has been published: %w", err)
	}
	return rows, nil
}
