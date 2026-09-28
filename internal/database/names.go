// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"context"

	"github.com/uptrace/bun"
)

// NamesByID reads one text value per row for a list of row identifiers, as a
// map from identifier to value. An identifier no row carries is absent from
// the answer.
//
// The list is split the way InAnyOf splits it, so a list of any length is one
// statement every engine takes. Table and column are Expr for the reason
// InAnyOf's column is: a placeholder cannot bind either, so both are spliced
// into the statement, and only text the caller wrote reaches it (REQ-66). The
// column may be composed, such as a display name falling back to another
// column.
func NamesByID(ctx context.Context, db bun.IDB, table, column Expr, ids []int64) (map[int64]string, error) {
	named := make(map[int64]string, len(ids))
	if len(ids) == 0 {
		return named, nil
	}
	where, args := InAnyOf(`"id"`, ids)
	var rows []struct {
		ID    int64  `bun:"id"`
		Named string `bun:"named"`
	}
	if err := db.NewSelect().
		TableExpr(string(table)).
		ColumnExpr(`"id" AS "id"`).
		ColumnExpr(string(column)+` AS "named"`).
		Where(where, args...).
		Scan(ctx, &rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		named[row.ID] = row.Named
	}
	return named, nil
}
