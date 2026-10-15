// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// graphNodeV090 is v0.9.0's declaration of the graph node table.
//
// The baseline's, with the source package a build stated for the component
// beside the identifiers it already holds. Derived from the baseline's
// declaration, which v0.5.0's record of its schema holds.
func graphNodeV090(t *columnTypes) []string {
	statements := graphNodeBaseline(t)
	statements[0] = withColumn(statements[0], `"cpe"            `+t.text+` NULL,`,
		`-- The source package this build stated the component was built
			-- from, and the version it was built at, as it stated them. The
			-- component row holds what the first report of it stated, and a
			-- source package one product states is not what another does.
			-- A scanner is given these.
			"upstream_name"    `+t.free+` NULL,
			"upstream_version" `+t.free+` NULL,`)
	return statements
}

// graphNodeUpstreamV090 adds the source package a build stated to each node,
// and fills it on every node v0.8.0 recorded from the component the node
// holds: that is what a v0.8.0 scanner was given for it. On v0.8.0 that value
// can be another product's statement. A moving line's next scan replaces it
// with what the build states; a tag is not uploaded again and keeps it.
func graphNodeUpstreamV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	// Stepped over where it is there already. MySQL and MariaDB commit the
	// columns as they are added, so a start that stopped before the fill
	// below finds them.
	present, err := u.hasColumn("graph_node", "upstream_version")
	if err != nil {
		return err
	}
	if !present {
		if err := u.change(graphNodeV090(t), change{table: "graph_node",
			add: []added{{column: "upstream_name"}, {column: "upstream_version"}}}); err != nil {
			return err
		}
	}
	return u.run([]string{
		`UPDATE "graph_node" SET
			"upstream_name" = (SELECT "c"."upstream_name" FROM "component" AS "c"
				WHERE "c"."id" = "graph_node"."component_id"),
			"upstream_version" = (SELECT "c"."upstream_version" FROM "component" AS "c"
				WHERE "c"."id" = "graph_node"."component_id")`,
	})
}
