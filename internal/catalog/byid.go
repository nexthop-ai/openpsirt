// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"fmt"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// StreamsByID names the branches and tags already known by identifier, in one
// read. An identifier that names nothing is absent from the answer.
//
// A credential and a target both carry identifiers, and a screen listing
// either says the names somebody typed.
func (s *Store) StreamsByID(ctx context.Context, ids []int64) (map[int64]Stream, error) {
	by := make(map[int64]Stream, len(ids))
	if len(ids) == 0 {
		return by, nil
	}
	var rows []Stream
	where, args := database.InAnyOf(`"s"."id"`, ids)
	if err := s.db.NewSelect().Model(&rows).Where(where, args...).Scan(ctx); err != nil {
		return nil, fmt.Errorf("look up streams by identifier: %w", err)
	}
	for _, row := range rows {
		by[row.ID] = row
	}
	return by, nil
}

// VariantsByID names the variants already known by identifier, in one read.
// An identifier that names nothing is absent from the answer.
func (s *Store) VariantsByID(ctx context.Context, ids []int64) (map[int64]Variant, error) {
	by := make(map[int64]Variant, len(ids))
	if len(ids) == 0 {
		return by, nil
	}
	var rows []Variant
	where, args := database.InAnyOf(`"v"."id"`, ids)
	if err := s.db.NewSelect().Model(&rows).Where(where, args...).Scan(ctx); err != nil {
		return nil, fmt.Errorf("look up variants by identifier: %w", err)
	}
	for _, row := range rows {
		by[row.ID] = row
	}
	return by, nil
}
