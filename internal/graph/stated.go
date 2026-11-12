// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"
)

// A component's name and version are read from the build's node. The
// component row holds what the first report of the component stated, and a
// package identifier names one component whatever version field a report puts
// beside it, so the row's can be another product's. A node written before the
// node kept them holds null, and reads the row's.
//
// Each takes the aliases a query gives the tables, as written in it.

// NodeName is the name a build stated, where the query joins the node as node
// and the component as component.
func NodeName(node, component string) string {
	return `COALESCE("` + node + `"."name", "` + component + `"."name")`
}

// NodeFolded is the name a build stated, folded as a component's name is, where
// the query joins the node as node and the component as component. A listing
// that groups by name groups by this, so a row is grouped under the name it is
// shown with.
func NodeFolded(node, component string) string {
	return `COALESCE("` + node + `"."name_folded", "` + component + `"."name_folded")`
}

// NodeVersion is the version a build stated, where the query joins the node as
// node and the component as component.
func NodeVersion(node, component string) string {
	return `COALESCE("` + node + `"."version", "` + component + `"."version")`
}

// StatedJoin joins, as alias, the node the build holds the component at now,
// where the query names the build and the component by the columns build and
// componentID. A build holds one open node for a component, so the join adds
// no row; a component the build no longer holds joins nothing. NodeName and
// NodeVersion then read the row's; StatedName and StatedVersion read the
// build's latest node, closed included, before the row's.
func StatedJoin(alias, build, componentID string) string {
	return `LEFT JOIN "graph_node" AS "` + alias + `" ON "` + alias + `"."build_id" = ` + build +
		` AND "` + alias + `"."component_id" = ` + componentID +
		` AND "` + alias + `"."closed_scan_id" IS NULL`
}

// StatedName is the name a build stated for a component joined through
// StatedJoin as alias: the open node's, else the build's latest node's, else
// the row's. The latest node is read only where no node is open, which is a
// component the build no longer holds, so a list of what is open pays nothing
// for it. Not for GROUP BY, since the fallback reads ungrouped columns.
func StatedName(alias, build, componentID, component string) string {
	return `COALESCE("` + alias + `"."name", ` + BuildName(build, componentID, component) + `)`
}

// StatedVersion is StatedName's version.
func StatedVersion(alias, build, componentID, component string) string {
	return `COALESCE("` + alias + `"."version", ` + BuildVersion(build, componentID, component) + `)`
}

// BuildName is the name a build stated for a component, where the query names
// the build and the component by the columns build and componentID and joins
// the component as component, but no node. It reads the build's latest node
// holding the component.
func BuildName(build, componentID, component string) string {
	return statedColumn("name", build, componentID, component)
}

// BuildVersion is BuildName's version.
func BuildVersion(build, componentID, component string) string {
	return statedColumn("version", build, componentID, component)
}

// statedColumn names both values of the root flag so that the index led by
// the build, the flag and the component answers it on PostgreSQL, which has no
// index led by the build and the component: without it, each row read every
// node of the build, 830 ms for 60 components of a build with 62,001 nodes.
func statedColumn(column, build, componentID, component string) string {
	return `COALESCE((SELECT "sn"."` + column + `" FROM "graph_node" AS "sn"` +
		` WHERE "sn"."build_id" = ` + build + ` AND "sn"."is_root" IN (FALSE, TRUE)` +
		` AND "sn"."component_id" = ` + componentID +
		` ORDER BY "sn"."opened_scan_id" DESC, "sn"."id" DESC LIMIT 1), "` + component + `"."` + column + `")`
}

// NamedAs answers the components a name somebody typed names among the open
// nodes the condition holds, written against the node as "n": those whose
// row's name folds to it, and those the build stated under it. Each is its own
// statement, because one condition across the two tables is answered by
// reading every node the condition holds, where apart each is led by an index:
// the component's fold, and the node's build and fold.
func NamedAs(ctx context.Context, db bun.IDB, name, where string, args ...any) ([]int64, error) {
	folded := Folded(name)
	var byRow, byNode []int64
	if err := db.NewSelect().Distinct().TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`"n"."component_id"`).
		Where(where, args...).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"c"."name_folded" = ?`, folded).
		Scan(ctx, &byRow); err != nil {
		return nil, fmt.Errorf("read the components named %q: %w", name, err)
	}
	if err := db.NewSelect().Distinct().TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."component_id"`).
		Where(where, args...).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."name_folded" = ?`, folded).
		Scan(ctx, &byNode); err != nil {
		return nil, fmt.Errorf("read the components stated as %q: %w", name, err)
	}
	seen := make(map[int64]bool, len(byRow)+len(byNode))
	ids := make([]int64, 0, len(byRow)+len(byNode))
	for _, id := range append(byRow, byNode...) {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids, nil
}
