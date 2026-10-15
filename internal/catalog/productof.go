// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"fmt"
)

// ProductOf is which product a build belongs to.
//
// Here because the catalog owns the relationship between a build, its stream
// and its product, and every package that asks delegates here. A build that
// does not exist answers ErrNotFound, and a database that cannot answer says
// so in an error of its own.
func (s *Store) ProductOf(ctx context.Context, targetID int64) (int64, error) {
	var productID int64
	err := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		ColumnExpr(`"st"."product_id"`).
		Where(`"tg"."id" = ?`, targetID).
		Scan(ctx, &productID)
	if err != nil {
		return 0, missingOr(err, fmt.Sprintf("build %d", targetID),
			fmt.Sprintf("look up which product build %d belongs to", targetID))
	}
	return productID, nil
}
