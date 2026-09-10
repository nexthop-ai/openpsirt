package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/pressly/goose/v3"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

func init() {
	goose.AddMigrationContext(upGraph, downGraph)
}

// The dependency graph, and the components in it.
//
// Components are global and deduplicated: the same library at the same version
// is one row however many products ship it. Without that, a component shared
// across a portfolio is stored once per variant per scan, and the row count
// grows with the product catalog rather than with reality.
//
// Nodes and edges are held with validity intervals rather than one set per
// scan. A nightly rebuild changes very little, so recording only what changed
// keeps stored volume tracking change rather than tracking scans.
func upGraph(ctx context.Context, tx *sql.Tx) error {
	e := migrate.EngineFrom(ctx)
	t := typesFor(e)
	if t == nil {
		return fmt.Errorf("no schema for %s", e)
	}

	statements := []string{
		// identity is derived from the component's own content — its package
		// identifier, or its name and version where it has none. Never from an
		// identifier the scan file supplied, which nothing guarantees is
		// stable between builds.
		`CREATE TABLE "component" (
			"id"               ` + t.id + `,
			"identity"         ` + t.hash + ` NOT NULL,
			"purl"             ` + t.text + ` NULL,
			-- Everything below comes from a scan file, and nothing bounds
			-- what a producer puts in it. A bounded column here means a
			-- legitimate but long value fails the whole scan that carried it.
			"name"             ` + t.free + ` NOT NULL,
			"version"          ` + t.free + ` NOT NULL,
			"upstream_name"    ` + t.free + ` NULL,
			"upstream_version" ` + t.free + ` NULL,
			-- The binary packages one source package was built at one version
			-- share this, and it is what a person acts on: curl, libcurl4t64
			-- and libcurl3t64 are one bump. It groups and does not identify —
			-- identity above is what every record hangs off, and none of them
			-- moves when a producer starts stating a source package it did
			-- not state before. Hashed, so that grouping cannot merge two
			-- source packages by agreeing to an index's bound.
			"fold_key"         ` + t.hash + ` NOT NULL,
			"first_seen_at"    ` + t.timestamp + ` NOT NULL,
			CONSTRAINT "component_identity_unique" UNIQUE ("identity")
		)` + t.suffix,

		// Not unique: a fold is many components by construction.
		`CREATE INDEX "component_fold_idx" ON "component" ("fold_key")`,

		// A node is one component's presence in one variant. The graph is a
		// graph, not a tree: a component reached by several parents is one
		// node with several edges, not one node per route. Enumerating routes
		// is a separate question, deliberately left until real data can say
		// how much a real graph shares.
		//
		// opened_scan_id and closed_scan_id are the interval. A NULL close
		// means the node is present now.
		`CREATE TABLE "graph_node" (
			"id"             ` + t.id + `,
			"target_id"      ` + t.ref + ` NOT NULL,
			"component_id"   ` + t.ref + ` NOT NULL,
			"is_root"        ` + t.boolean + ` NOT NULL,
			"opened_scan_id" ` + t.ref + ` NOT NULL,
			"closed_scan_id" ` + t.refNull + ` NULL,
			CONSTRAINT "graph_node_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "graph_node_component_fk" FOREIGN KEY ("component_id") REFERENCES "component"("id"),
			CONSTRAINT "graph_node_opened_fk" FOREIGN KEY ("opened_scan_id") REFERENCES "scan"("id"),
			CONSTRAINT "graph_node_closed_fk" FOREIGN KEY ("closed_scan_id") REFERENCES "scan"("id")
		)` + t.suffix,

		`CREATE TABLE "graph_edge" (
			"id"             ` + t.id + `,
			"target_id"      ` + t.ref + ` NOT NULL,
			"parent_id"      ` + t.ref + ` NOT NULL,
			"child_id"       ` + t.ref + ` NOT NULL,
			"opened_scan_id" ` + t.ref + ` NOT NULL,
			"closed_scan_id" ` + t.refNull + ` NULL,
			CONSTRAINT "graph_edge_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "graph_edge_parent_fk" FOREIGN KEY ("parent_id") REFERENCES "graph_node"("id"),
			CONSTRAINT "graph_edge_child_fk" FOREIGN KEY ("child_id") REFERENCES "graph_node"("id"),
			CONSTRAINT "graph_edge_opened_fk" FOREIGN KEY ("opened_scan_id") REFERENCES "scan"("id"),
			CONSTRAINT "graph_edge_closed_fk" FOREIGN KEY ("closed_scan_id") REFERENCES "scan"("id")
		)` + t.suffix,

		// "What is present now" is the question asked on every ingest and by
		// every view, so it gets an index rather than a filter over history.
		`CREATE INDEX "graph_node_current_idx" ON "graph_node" ("target_id", "closed_scan_id", "component_id")`,
		`CREATE INDEX "graph_edge_current_idx" ON "graph_edge" ("target_id", "closed_scan_id", "parent_id", "child_id")`,
		`CREATE INDEX "graph_edge_child_idx" ON "graph_edge" ("child_id", "closed_scan_id")`,
	}

	for _, stmt := range statements {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%s: %w", firstLine(stmt), err)
		}
	}
	return nil
}

func downGraph(ctx context.Context, tx *sql.Tx) error {
	for _, table := range []string{"graph_edge", "graph_node", "component"} {
		if _, err := tx.ExecContext(ctx, `DROP TABLE `+table); err != nil {
			return err
		}
	}
	return nil
}
