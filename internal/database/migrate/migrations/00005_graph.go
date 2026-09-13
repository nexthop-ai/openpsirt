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
			-- The second identifier a component can carry.
			--
			-- The package identifier is what identity is derived from and
			-- what most feeds match on. The platform enumeration is what the
			-- national vulnerability database keys on, and a scanner given
			-- one matches components a package identifier alone misses:
			-- vendor firmware, operating systems, appliances, anything never
			-- published to a package ecosystem. Captured because a real
			-- producer emits it for most of what it ships and a scan file is
			-- not kept once read — data discarded at ingest is recoverable
			-- only by asking the producer to build again.
			--
			-- Deliberately not part of identity: adding a second basis would
			-- move the identity of everything carrying both.
			"cpe"              ` + t.text + ` NULL,
			-- Everything below comes from a scan file, and nothing bounds
			-- what a producer puts in it. A bounded column here means a
			-- legitimate but long value fails the whole scan that carried it.
			"name"             ` + t.free + ` NOT NULL,
			"version"          ` + t.free + ` NOT NULL,
			"upstream_name"    ` + t.free + ` NULL,
			"upstream_version" ` + t.free + ` NULL,
			-- The two names, folded, for matching a name somebody typed.
			--
			-- Bounded, unlike the names they fold: the stored name is
			-- unbounded because nothing bounds what a producer puts in a scan
			-- file, and a bounded column there would fail a whole scan over
			-- one long value. These exist to be looked up, and an index needs
			-- a width — truncated on the way in rather than refused, because
			-- two names agreeing for a hundred and ninety-one characters are
			-- the same name by any reading.
			--
			-- Folded in Go rather than by asking an engine to compare
			-- loosely, because the four do not agree on what that means: a
			-- rule naming a package with a capital in it sweeps on two of
			-- them and not the other two, and nothing reports the difference
			-- because both answers look correct. It also makes the
			-- comparisons use an index, where LOWER(name) cannot — every
			-- routing sweep and every component search was a scan of this
			-- table.
			--
			-- Nullable, because a component with no upstream name recorded
			-- has no folded one either.
			"name_folded"      ` + t.name + ` NULL,
			"upstream_folded"  ` + t.name + ` NULL,
			-- The binary packages one source package was built at one version
			-- share this, and it is what a person acts on: curl, libcurl4t64
			-- and libcurl3t64 are one bump. It groups and does not identify —
			-- identity above is what every record hangs off, and none of them
			-- moves when a producer starts stating a source package it did
			-- not state before. Hashed, so that grouping cannot merge two
			-- source packages by agreeing to an index's bound.
			"fold_key"         ` + t.hash + ` NOT NULL,
			"first_seen_at"    ` + t.timestamp + ` NOT NULL,
			-- What upstream has released, and when we last asked.
			--
			-- Kept because "we have never asked" and "we asked and it has not
			-- moved" are different states: without the third column a
			-- component nobody could look up is indistinguishable from one
			-- that is current. Only for what we build ourselves — for a
			-- distribution package the distribution is the maintainer and its
			-- release date says nothing about the software inside, which is
			-- why these sit on the component rather than being inferred for
			-- everything.
			"latest_version"     ` + t.free + ` NULL,
			"latest_released_at" ` + t.timestamp + ` NULL,
			"latest_checked_at"  ` + t.timestamp + ` NULL,
			-- What the index says the package is, and where it is developed.
			-- Taken where an index serves them and absent where it does not,
			-- which is the ordinary case rather than a half-written row: three
			-- of the four serve a summary and the module proxy serves none,
			-- while all four name an address. Both are somebody else's text, so
			-- the summary is bounded and the address is judged before it is
			-- stored.
			"summary"            ` + t.free + ` NULL,
			"project_url"        ` + t.free + ` NULL,
			-- Who the producer said supplied it: a distribution, a vendor, a
			-- project. From the inventory rather than from an index, and absent
			-- for plenty of it — one producer states it for 759 of the 6,866
			-- components it describes. Not part of identity, because two
			-- producers name it differently or not at all.
			"supplier"           ` + t.free + ` NULL,
			CONSTRAINT "component_identity_unique" UNIQUE ("identity")
		)` + t.suffix,

		// Not unique: a fold is many components by construction.
		`CREATE INDEX "component_fold_idx" ON "component" ("fold_key")`,

		// What a routing rule and a component search look one up by. The
		// upstream name matters most, because a rule names a source package:
		// that is the key one rule uses to reach every binary package built
		// from it.
		`CREATE INDEX "component_folded_idx" ON "component" ("name_folded")`,
		`CREATE INDEX "component_upstream_folded_idx" ON "component" ("upstream_folded")`,

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
		// Quoted, like every other identifier in the schema. A reserved word
		// is only reserved when bare, and the four engines do not agree on
		// which words those are — so an unquoted name fails on whichever
		// engine somebody is least likely to be running.
		if _, err := tx.ExecContext(ctx, `DROP TABLE "`+table+`"`); err != nil {
			return err
		}
	}
	return nil
}
