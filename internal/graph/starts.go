// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// MostStarts is the most components one package identifier may start a walk
// at: a repository a build ships at a few commits is a few starts, and a
// walk from many is a different question asked by accident.
const MostStarts = 20

// ComponentsOf is the components a build holds live whose package identifier
// names the package a prefix chooses, in identifier order, or none.
//
// The type narrows the statement, bound and escaped; the package is tested
// here, on the identifier reduced as identity reduces it, since no stored
// column holds it that way.
func (s *Store) ComponentsOf(ctx context.Context, buildID int64, pkg PurlPrefix) ([]int64, error) {
	if pkg.Empty() {
		return nil, nil
	}
	var rows []struct {
		ID   int64  `bun:"id"`
		Purl string `bun:"purl"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`DISTINCT "c"."id" AS "id", "c"."purl" AS "purl"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`LOWER("c"."purl") LIKE ?`+database.LikeClause, pkg.TypePattern()).
		OrderExpr(`"c"."id"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the components of build %d named %s: %w", buildID, pkg, err)
	}
	var out []int64
	for _, row := range rows {
		if pkg.Matches(row.Purl) {
			out = append(out, row.ID)
		}
	}
	return out, nil
}

// TypePattern is a pattern for a lowercased identifier, bound beside the
// engine's escape clause, keeping those of the prefix's type: the part of the
// choice a statement can make, the package being tested on each one read.
//
// The type is read off the prefix itself, since a path naming only a type,
// such as `pkg:deb/`, names no package to parse.
func (p PurlPrefix) TypePattern() string {
	kind, _, _ := strings.Cut(strings.TrimPrefix(p.wanted, "pkg:"), "/")
	return "pkg:" + database.LikeEscaped(kind) + "/%"
}

// Path is whether the prefix names everything under a path rather than one
// package.
func (p PurlPrefix) Path() bool { return p.under }
