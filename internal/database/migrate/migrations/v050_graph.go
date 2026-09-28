// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// v0.5.0's declaration of the graph node table, and its index.
//
// v0.1.0's, which no release since changed, with the identifiers a build
// states for a component.
func graphNodeV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "graph_node" (
			"id"             ` + t.id + `,
			"target_id"      ` + t.ref + ` NOT NULL,
			"component_id"   ` + t.ref + ` NOT NULL,
			"is_root"        ` + t.boolean + ` NOT NULL,
			"opened_scan_id" ` + t.ref + ` NOT NULL,
			"closed_scan_id" ` + t.refNull + ` NULL,
			-- The package identifier and the platform enumeration this build
			-- stated for the component, as it stated them. The component row
			-- is shared by every product shipping the package, and a
			-- distribution qualifier or an enumeration one build states is
			-- not what another does. A scanner is given these. Unbounded, as
			-- the component's own are.
			"purl"           ` + t.text + ` NULL,
			"cpe"            ` + t.text + ` NULL,
			CONSTRAINT "graph_node_target_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "graph_node_component_fk" FOREIGN KEY ("component_id") REFERENCES "component"("id"),
			CONSTRAINT "graph_node_opened_fk" FOREIGN KEY ("opened_scan_id") REFERENCES "scan"("id"),
			CONSTRAINT "graph_node_closed_fk" FOREIGN KEY ("closed_scan_id") REFERENCES "scan"("id")
		)` + t.suffix,

		`CREATE INDEX "graph_node_current_idx" ON "graph_node" ("target_id", "closed_scan_id", "component_id")`,
	}
}
