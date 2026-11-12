// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// BranchesAndTagsByID names the branches and tags already known by identifier, in one
// read. An identifier that names nothing is absent from the answer.
//
// A credential and a build both carry identifiers, and a screen listing
// either says the names somebody typed.
func (s *Store) BranchesAndTagsByID(ctx context.Context, ids []int64) (map[int64]BranchOrTag, error) {
	return rowsByID(ctx, s.db, `"s"."id"`, ids, func(row BranchOrTag) int64 { return row.ID },
		"branches and tags")
}

// VariantsByID names the variants already known by identifier, in one read.
// An identifier that names nothing is absent from the answer.
func (s *Store) VariantsByID(ctx context.Context, ids []int64) (map[int64]Variant, error) {
	return rowsByID(ctx, s.db, `"v"."id"`, ids, func(row Variant) int64 { return row.ID }, "variants")
}

// rowsByID reads the rows of one model whose identifier, the column column,
// is among ids, keyed by identifier. what names the rows in the error.
func rowsByID[T any](ctx context.Context, db bun.IDB, column database.Expr, ids []int64,
	idOf func(T) int64, what string) (map[int64]T, error) {

	by := make(map[int64]T, len(ids))
	if len(ids) == 0 {
		return by, nil
	}
	var rows []T
	where, args := database.InAnyOf(column, ids)
	if err := db.NewSelect().Model(&rows).Where(where, args...).Scan(ctx); err != nil {
		return nil, fmt.Errorf("look up %s by identifier: %w", what, err)
	}
	for _, row := range rows {
		by[idOf(row)] = row
	}
	return by, nil
}
