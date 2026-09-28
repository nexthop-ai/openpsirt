// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog

import "github.com/uptrace/bun"

// What a product, a stream or a variant is called on a screen: its display
// name, or its name where it has none.
//
// One rule for every reader and every endpoint. A label that is blank on one
// list and the name on another leaves each screen to invent its own fallback,
// and two screens inventing one disagree.

// Shown is what a row already read is called on a screen.
func Shown(displayName, name string) string {
	if displayName != "" {
		return displayName
	}
	return name
}

// ShownExpr is Shown as SQL, over the row a statement aliases as alias.
//
// The alias is spliced into the statement, so only text a caller wrote in
// code reaches it (REQ-66).
func ShownExpr(alias string) string {
	return `COALESCE(NULLIF(` + alias + `.display_name, ''), ` + alias + `.name)`
}

// BuildNames adds the six columns that name a build — its product, stream and
// variant, each by name and as shown — to a statement joining those three rows
// under these aliases. Passed to Apply. A grouped statement groups by each
// row's name and display name.
func BuildNames(product, stream, variant string) func(*bun.SelectQuery) *bun.SelectQuery {
	return func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.
			ColumnExpr(product + `.name AS "product"`).
			ColumnExpr(ShownExpr(product) + ` AS "product_name"`).
			ColumnExpr(stream + `.name AS "stream"`).
			ColumnExpr(ShownExpr(stream) + ` AS "stream_name"`).
			ColumnExpr(variant + `.name AS "variant"`).
			ColumnExpr(ShownExpr(variant) + ` AS "variant_name"`)
	}
}
