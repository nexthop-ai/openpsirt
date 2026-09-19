package catalog

import (
	"context"
	"fmt"
)

// ProductOf is which product a build belongs to.
//
// Here because the catalog owns the relationship between a build, its stream
// and its product. A copy per package differs: one wraps the driver's error
// and one replaces it with a fixed sentence, so on that side a database that
// cannot answer and a build that does not exist come back identically.
func (s *Store) ProductOf(ctx context.Context, targetID int64) (int64, error) {
	var productID int64
	err := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("st.product_id").
		Where("tg.id = ?", targetID).
		Scan(ctx, &productID)
	if err != nil {
		return 0, missingOr(err, fmt.Sprintf("build %d", targetID),
			fmt.Sprintf("look up which product build %d belongs to", targetID))
	}
	return productID, nil
}
