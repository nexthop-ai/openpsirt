// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"slices"
	"sort"
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

// Reached is what one name reaches in some builds: the folds it names, and
// the components that were ever the root of a build whose root it names.
type Reached struct {
	// Folds is every fold the name reaches, the former roots' included.
	Folds []string
	// Roots is the components that were ever the root of a build the name
	// names the root of. A component that was ever a build's root is the build
	// itself, so a code finding placed on one is on the build.
	Roots []int64
}

// ReachedByName is what each of these names reaches in these builds, keyed by
// the name folded, as the component screen reaches a name: a live component of
// the name in one of the builds, or one built from a source of the name, and
// the fold each is in. A version narrows to what was built at it. A name that
// names a build's root reaches every component that was ever its root as
// well, at that version where one is named. A blank name reaches nothing.
//
// Read on its own and answered as values, for the reason FoldsNamed is: as a
// subquery its size is the planner's estimate, and on MySQL the estimate
// probed the fold index once per code finding.
func ReachedByName(ctx context.Context, db bun.IDB, buildIDs []int64, names []string,
	version string) (map[string]Reached, error) {

	out := map[string]Reached{}
	list := namedOnce(names)
	if len(list) == 0 || len(buildIDs) == 0 {
		return out, nil
	}
	asked := map[string]bool{}
	for _, name := range list {
		asked[name] = true
	}
	version = strings.TrimSpace(version)
	narrowed := func(q *bun.SelectQuery) *bun.SelectQuery {
		if version != "" {
			return q.Where(sourceVersionOf+" = ?", version)
		}
		return q
	}

	var live []struct {
		Name     string `bun:"name_folded"`
		Upstream string `bun:"upstream_folded"`
		Fold     string `bun:"fold_key"`
		BuildID  int64  `bun:"build_id"`
		Root     bool   `bun:"is_root"`
	}
	if err := narrowed(foldsNamed(db, buildIDs, list...).
		ColumnExpr(`"cn"."name_folded", COALESCE("cn"."upstream_folded", '') AS "upstream_folded"`).
		ColumnExpr(`"cn"."fold_key", "nn"."build_id", "nn"."is_root"`).
		Distinct()).
		Scan(ctx, &live); err != nil {
		return nil, fmt.Errorf("read what %d names reach in these builds: %w", len(list), err)
	}
	folds := map[string]map[string]bool{}
	add := func(name, fold string) {
		if folds[name] == nil {
			folds[name] = map[string]bool{}
		}
		folds[name][fold] = true
	}
	rooted := map[string]map[int64]bool{}
	var rootBuilds []int64
	seen := map[int64]bool{}
	for _, row := range live {
		for _, name := range []string{row.Name, row.Upstream} {
			if !asked[name] {
				continue
			}
			add(name, row.Fold)
			if !row.Root {
				continue
			}
			if rooted[name] == nil {
				rooted[name] = map[int64]bool{}
			}
			rooted[name][row.BuildID] = true
			if !seen[row.BuildID] {
				seen[row.BuildID] = true
				rootBuilds = append(rootBuilds, row.BuildID)
			}
		}
	}
	// Every root each build whose root a name names has had, at the version
	// asked for.
	roots, err := graph.RootsOf(ctx, db, rootBuilds)
	if err != nil {
		return nil, err
	}
	foldOf := map[int64]string{}
	if len(roots) > 0 {
		ids := make([]int64, 0, len(roots))
		for _, root := range roots {
			ids = append(ids, root.ComponentID)
		}
		var rows []struct {
			ID   int64  `bun:"id"`
			Fold string `bun:"fold_key"`
		}
		if err := narrowed(db.NewSelect().TableExpr(`"component" AS "cn"`).
			ColumnExpr(`"cn"."id", "cn"."fold_key"`).
			Where(`"cn"."id" IN (?)`, bun.List(ids))).
			Scan(ctx, &rows); err != nil {
			return nil, fmt.Errorf("read the folds of %d roots: %w", len(ids), err)
		}
		for _, row := range rows {
			foldOf[row.ID] = row.Fold
		}
	}
	for name, builds := range rooted {
		ids := map[int64]bool{}
		for _, root := range roots {
			if fold, ok := foldOf[root.ComponentID]; ok && builds[root.BuildID] {
				add(name, fold)
				ids[root.ComponentID] = true
			}
		}
		reached := out[name]
		for id := range ids {
			reached.Roots = append(reached.Roots, id)
		}
		slices.Sort(reached.Roots)
		out[name] = reached
	}
	for name, set := range folds {
		reached := out[name]
		for fold := range set {
			reached.Folds = append(reached.Folds, fold)
		}
		sort.Strings(reached.Folds)
		out[name] = reached
	}
	return out, nil
}

// OpenByName is how many distinct keys open findings hold on what each name
// reaches, where the reach of each name is given and the findings are a
// statement answering "fold_key" and "key", one row per distinct pair; a key
// is a string or an identifier, which scans as its digits. The union per name
// is taken here: one key on two folds of a name, at two versions in two
// builds, is counted once.
func OpenByName(ctx context.Context, keyed *bun.SelectQuery, reached map[string]Reached) (map[string]int, error) {
	out := map[string]int{}
	var rows []struct {
		Fold string `bun:"fold_key"`
		Key  string `bun:"key"`
	}
	if err := keyed.Scan(ctx, &rows); err != nil {
		return nil, err
	}
	byFold := map[string][]string{}
	for _, row := range rows {
		byFold[row.Fold] = append(byFold[row.Fold], row.Key)
	}
	for name, r := range reached {
		keys := map[string]bool{}
		for _, fold := range r.Folds {
			for _, key := range byFold[fold] {
				keys[key] = true
			}
		}
		out[name] = len(keys)
	}
	return out, nil
}

// FoldsOf is every fold these names reach, each once.
func FoldsOf(reached map[string]Reached) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reached {
		for _, fold := range r.Folds {
			if !seen[fold] {
				seen[fold] = true
				out = append(out, fold)
			}
		}
	}
	sort.Strings(out)
	return out
}

// OpenIssuesOf is the distinct issues open on each matched source package in
// its product's builds in scope, of what the subject reads there: the
// findings lists' kinds, at the visibilities they read. A match in a product
// where they read no dependency finding has no entry.
//
// What each name reaches is read first and bound as values, and the issues
// are read once per fold and issue: a fold of ten binaries carries each issue
// ten times, and joined per binary the engine sorted every copy, 1.28 million
// rows for 128 thousand on a kernel of ten binaries.
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
		builds := matches[at[0]].Builds
		names := make([]string, 0, len(at))
		for _, i := range at {
			names = append(names, matches[i].Folded)
		}
		reached, err := ReachedByName(ctx, s.db, builds, names, "")
		if err != nil {
			return nil, err
		}
		issues := map[string]int{}
		if folds := FoldsOf(reached); len(folds) > 0 {
			keyed := s.db.NewSelect().TableExpr(`"finding" AS "f"`).
				Join(`JOIN "component" AS "pc" ON "pc"."id" = "f"."component_id"`).
				ColumnExpr(`"pc"."fold_key", "f"."vulnerability_id" AS "key"`).
				Where(`"f"."build_id" IN (?)`, bun.List(builds)).
				Where(`"pc"."fold_key" IN (?)`, bun.List(folds)).
				Where(`"f"."closed_at" IS NULL`).
				Where(`"f"."visibility" IN (?)`, bun.List(visible)).
				Where(kinds, kindArgs...).
				Distinct()
			if issues, err = OpenByName(ctx, keyed, reached); err != nil {
				return nil, fmt.Errorf("count the open issues on components of product %d: %w", productID, err)
			}
		}
		for _, i := range at {
			out[i] = issues[matches[i].Folded]
		}
	}
	return out, nil
}
