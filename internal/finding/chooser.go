// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// SourceMatch is one source package a term names in one product.
type SourceMatch struct {
	ProductID int64  `bun:"product_id"`
	Product   string `bun:"product"`
	// Source is the source package as a producer spelled it, and Folded the
	// name it is matched and counted under.
	Source string `bun:"source_name"`
	Folded string `bun:"source_folded"`
	// Builds is the builds in scope of the product, which every count over
	// the match is taken across.
	Builds []int64 `bun:"-"`
}

// sourceFolded is the name a component's source package is matched under:
// the source it states, else its own name, both folded for capitals.
const sourceFolded = `CASE WHEN COALESCE("c"."upstream_folded", '') <> '' THEN "c"."upstream_folded" ELSE "c"."name_folded" END`

// Matching is the source packages whose own name or a binary's holds a term,
// in the builds a scope covers, one per product and source, for a chooser
// leading to the component page. A product with no scope named is every
// product the subject reads findings in; a product they read nothing in is
// never searched, because its inventory is the breadth they were not granted.
//
// An exact name first, then by name, then by product, cut at limit.
func (s *Store) Matching(ctx context.Context, subject access.Subject, scope Scope,
	term string, limit int) ([]SourceMatch, error) {

	term = strings.TrimSpace(term)
	if term == "" {
		return nil, nil
	}
	var products []int64
	if scope.ProductID != nil {
		if _, err := access.Readable(subject, *scope.ProductID); err != nil {
			return nil, err
		}
		products = []int64{*scope.ProductID}
	} else {
		held, all := subject.Products()
		if all {
			if err := s.db.NewSelect().TableExpr(`"product" AS "p"`).ColumnExpr(`"p"."id"`).
				OrderExpr(`"p"."id"`).Scan(ctx, &held); err != nil {
				return nil, fmt.Errorf("read the products: %w", err)
			}
		}
		for _, id := range held {
			if _, err := access.Readable(subject, id); err == nil {
				products = append(products, id)
			}
		}
	}
	if len(products) == 0 {
		return nil, nil
	}
	var builds []struct {
		ID        int64 `bun:"id"`
		ProductID int64 `bun:"product_id"`
	}
	q := s.db.NewSelect().TableExpr(`"build" AS "tg"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"tg"."id", "st"."product_id"`).
		Where(`"st"."product_id" IN (?)`, bun.List(products))
	if err := scope.Narrow(q).OrderExpr(`"tg"."id"`).Scan(ctx, &builds); err != nil {
		return nil, fmt.Errorf("read the builds to search: %w", err)
	}
	if len(builds) == 0 {
		return nil, nil
	}
	ids := make([]int64, len(builds))
	byProduct := map[int64][]int64{}
	for i, b := range builds {
		ids[i] = b.ID
		byProduct[b.ProductID] = append(byProduct[b.ProductID], b.ID)
	}

	like := "%" + database.LikeEscaped(graph.Folded(term)) + "%"
	shipped := s.db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "n"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(sourceFolded+` AS "source_folded"`).
		ColumnExpr(SourceName+` AS "source_name"`).
		Where(`"n"."build_id" IN (?)`, bun.List(ids)).
		Where(`"n"."closed_scan_id" IS NULL`).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr(`"c"."name_folded" LIKE ?`+database.LikeClause, like).
				WhereOr(`COALESCE("c"."upstream_folded", '') LIKE ?`+database.LikeClause, like)
		})
	var out []SourceMatch
	if err := s.db.NewSelect().TableExpr(`(?) AS "m"`, shipped).
		Join(`JOIN "product" AS "p" ON "p"."id" = "m"."product_id"`).
		ColumnExpr(`"m"."product_id", "p"."name" AS "product", "m"."source_folded"`).
		ColumnExpr(`MIN("m"."source_name") AS "source_name"`).
		GroupExpr(`"m"."product_id", "p"."name", "m"."source_folded"`).
		OrderExpr(`CASE WHEN "m"."source_folded" = ? THEN 0 ELSE 1 END, "m"."source_folded", "p"."name"`,
			graph.Folded(term)).
		Limit(int64(database.AList.Of(limit))).
		Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("find the components named %q: %w", term, err)
	}
	for i := range out {
		out[i].Builds = byProduct[out[i].ProductID]
	}
	return out, nil
}

// NamedFolds is the fold keys each of these names reaches, as the component
// page reaches them: a component of the name, or one built from a source of
// the name. A derived table of the name, as "asked", and the fold key, joined
// as "nf"; the arguments follow the statement.
func NamedFolds(names []string) (string, []any) {
	return `(SELECT "cn"."name_folded" AS "asked", "cn"."fold_key" AS "fold_key"
		FROM "component" AS "cn" WHERE "cn"."name_folded" IN (?)
		UNION ALL
		SELECT "cu"."upstream_folded", "cu"."fold_key"
		FROM "component" AS "cu" WHERE "cu"."upstream_folded" IN (?)) AS "nf"`,
		[]any{bun.List(names), bun.List(names)}
}

// OpenIssuesOf is the distinct issues open on each matched source package in
// its product's builds in scope, of what the subject reads there: the
// findings lists' kinds, at the visibilities they read. A match in a product
// where they read no dependency finding has no entry.
func (s *Store) OpenIssuesOf(ctx context.Context, subject access.Subject, matches []SourceMatch) (map[int]int, error) {
	out := map[int]int{}
	byProduct := map[int64][]int{}
	for i, m := range matches {
		byProduct[m.ProductID] = append(byProduct[m.ProductID], i)
	}
	kinds, kindArgs := kind.Triage.Where(`"f"."kind"`)
	for productID, at := range byProduct {
		if !subject.Reads(access.Public, productID) && !subject.Reads(access.Private, productID) {
			continue
		}
		visible := access.Visible(subject, productID)
		names := make([]string, 0, len(at))
		for _, i := range at {
			names = append(names, matches[i].Folded)
		}
		folds, foldArgs := NamedFolds(names)
		var counted []struct {
			Asked  string `bun:"asked"`
			Issues int    `bun:"issues"`
		}
		if err := s.db.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "component" AS "pc" ON "pc"."id" = "f"."component_id"`).
			Join(`JOIN `+folds+` ON "nf"."fold_key" = "pc"."fold_key"`, foldArgs...).
			ColumnExpr(`"nf"."asked", COUNT(DISTINCT "f"."vulnerability_id") AS "issues"`).
			Where(`"f"."build_id" IN (?)`, bun.List(matches[at[0]].Builds)).
			Where(`"f"."closed_at" IS NULL`).
			Where(`"f"."visibility" IN (?)`, bun.List(visible)).
			Where(kinds, kindArgs...).
			GroupExpr(`"nf"."asked"`).
			Scan(ctx, &counted); err != nil {
			return nil, fmt.Errorf("count the open issues on components of product %d: %w", productID, err)
		}
		issues := map[string]int{}
		for _, c := range counted {
			issues[c.Asked] = c.Issues
		}
		for _, i := range at {
			out[i] = issues[matches[i].Folded]
		}
	}
	return out, nil
}
