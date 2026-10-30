// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// graphNodeV0110 is v0.11.0's declaration of the graph node table.
//
// v0.9.0's, with the repository a build stated the component is built from,
// and an index of every root each build has had. Derived from v0.9.0's
// declaration; no release between changed it.
func graphNodeV0110(t *columnTypes) []string {
	statements := graphNodeV090(t)
	statements[0] = withColumn(statements[0], `"upstream_version" `+t.free+` NULL,`,
		`-- The version-control address this build stated the component is
			-- built from, without credentials. An analyzer's result in that
			-- repository is placed on the component.
			"repository"       `+t.free+` NULL,`)
	statements = append(statements,
		// Every root a build has had, live or closed. A node is never
		// deleted, so without it that read walks the build's whole history.
		`CREATE INDEX "graph_node_root_idx" ON "graph_node" ("target_id", "is_root", "component_id", "closed_scan_id")`)
	return renamedV0110(statements)
}

// graphNodeRepositoryV0110 adds the repository a build stated to each node.
// v0.10.0 kept none, so every node starts without one, and a build's next
// inventory states it.
func graphNodeRepositoryV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("graph_node", "repository")
	if err != nil || present {
		return err
	}
	return u.change(graphNodeV0110(u.t), change{table: "graph_node",
		add: []added{{column: "repository"}}})
}

// graphNodeRootIndexV0110 adds the index of every root each build has had.
func graphNodeRootIndexV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	return u.index(graphNodeV0110(u.t), "graph_node", "graph_node_root_idx")
}
