// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// graphNodeV0130 is v0.13.0's declaration of the graph node table.
//
// v0.11.0's, with the name and version the build stated for the component,
// the name's fold, the fold of the source package it stated, and an index of
// each build's nodes by each fold.
func graphNodeV0130(t *columnTypes) []string {
	statements := append([]string(nil), graphNodeV0110(t)...)
	statements[0] = withColumn(statements[0], `"repository"       `+t.free+` NULL,`,
		`-- The name and version this build stated for the component, as it
			-- stated them. The component row holds what the first report of
			-- it stated, and a package identifier names one component
			-- whatever version field beside it says. A scanner is given
			-- these, and every screen shows them. Null on a node written
			-- before they were kept, which reads the component's.
			"name"             `+t.free+` NULL,
			"version"          `+t.free+` NULL,
			-- The stated name folded as the component's is, which a name
			-- somebody types is matched on.
			"name_folded"      `+t.name+` NULL,
			-- The source package this build stated, else the stated name,
			-- folded: what an assignment rule's source pattern is matched
			-- on.
			"source_folded"    `+t.name+` NULL,`)
	statements = append(statements,
		// A typed name is looked up within one build, or the builds of
		// one product.
		`CREATE INDEX "graph_node_name_idx" ON "graph_node" ("build_id", "name_folded")`,
		// A rule's source pattern is looked up within the builds of one
		// product.
		`CREATE INDEX "graph_node_source_idx" ON "graph_node" ("build_id", "source_folded")`)
	return statements
}

// graphNodeStatedV0130 adds the name and version a build stated to each node,
// the name's fold, the stated source's fold, and the index of each. v0.12.0 kept none of them, so every
// node starts without them, and a build's next inventory states them. Each
// column is asked for alone: on MySQL and MariaDB a stop between two leaves
// the first added.
func graphNodeStatedV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if err := graphNodeColumnsV0130(u); err != nil {
		return err
	}
	return u.index(graphNodeV0130(u.t), "graph_node", "graph_node_name_idx", "graph_node_source_idx")
}

// graphNodeColumnsV0130 adds each of v0.13.0's node columns not already made.
func graphNodeColumnsV0130(u *upgrader) error {
	for _, column := range []string{"name", "version", "name_folded", "source_folded"} {
		present, err := u.hasColumn("graph_node", column)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.change(graphNodeV0130(u.t), change{table: "graph_node",
			add: []added{{column: column}}}); err != nil {
			return err
		}
	}
	return nil
}
