package catalog

import (
	"context"
	"fmt"
)

// ProductOf is which product a build belongs to.
//
// Here because two packages were each carrying their own copy of the same two
// joins, and the catalog is what owns the relationship between a build, its
// stream and its product. The copies had already begun to differ: one wrapped
// the driver's error and one replaced it with a fixed sentence, so on that side
// a database that could not answer and a build that does not exist came back
// identically.
func (s *Store) ProductOf(ctx context.Context, targetID int64) (int64, error) {
	var productID int64
	err := s.db.NewSelect().
		TableExpr(`"target" AS tg`).
		Join(`JOIN "stream" AS st ON st.id = tg.stream_id`).
		ColumnExpr("st.product_id").
		Where("tg.id = ?", targetID).
		Scan(ctx, &productID)
	if err != nil {
		return 0, fmt.Errorf("look up which product build %d belongs to: %w", targetID, err)
	}
	return productID, nil
}
