package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Level is what a count of what is open is grouped by.
//
// A closed set rather than a column name a caller supplies: a placeholder
// cannot bind an identifier, so a grouping column arriving from a request is
// the hole a parameterized query does not close.
type Level int

const (
	// ByProduct counts what is open against each product.
	ByProduct Level = iota
	// ByStream counts against each branch or tag.
	ByStream
	// ByVariant counts against each variant.
	ByVariant
)

func (l Level) column() (string, bool) {
	switch l {
	case ByProduct:
		return "st.product_id", true
	case ByStream:
		return "tg.stream_id", true
	case ByVariant:
		return "tg.variant_id", true
	}
	return "", false
}

// OpenBy counts what is open at each product, branch or variant.
//
// Counted as issues at components rather than as places, which is what the
// findings list counts and what a catalog row has to agree with. A component
// reached twenty ways carries the same issue twenty times, so counting rows
// makes a product look twenty times worse than the list somebody opens next.
//
// Worked out when it is asked for. A catalog is a handful of rows and the
// alternative is a stored total that is right at the end of a scan and drifts
// from the list beside it thereafter.
func (s *Store) OpenBy(ctx context.Context, subject access.Subject, scope Scope,
	level Level) (map[int64]int, error) {
	column, ok := level.column()
	if !ok {
		return nil, fmt.Errorf("no such grouping")
	}
	products, all := subject.Products()
	if subject.Kind != access.Person || (!all && len(products) == 0) {
		return map[int64]int{}, nil
	}

	inner := s.db.NewSelect().
		Distinct().
		TableExpr(`finding AS "f"`).
		Join(`JOIN target AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		ColumnExpr(column + ` AS "grouped_by"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		Where("f.closed_at IS NULL")
	if !all {
		inner = inner.Where("st.product_id IN (?)", bun.List(products))
	}
	inner = scope.Narrow(onlyVisible(inner, subject, products, all))

	var rows []struct {
		GroupedBy int64 `bun:"grouped_by"`
		Open      int   `bun:"open"`
	}
	err := s.db.NewSelect().
		TableExpr(`(?) AS "counted"`, inner).
		ColumnExpr(`counted.grouped_by AS "grouped_by"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		GroupExpr("counted.grouped_by").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("count what is open: %w", err)
	}

	out := make(map[int64]int, len(rows))
	for _, row := range rows {
		out[row.GroupedBy] = row.Open
	}
	return out, nil
}
